"""
This module provides a comprehensive set of tools for automating graphical user
interface (GUI) interactions and assertions within the SCAutolib framework.
It defines classes for capturing screenshots
(``Screen``), controlling mouse movements and clicks (``Mouse``), and managing
keyboard input (through ``keyboard`` python module).
The central ``GUI`` class orchestrates these interactions, allowing for the
creation of automated GUI test sequences with logging and visual verification
capabilities.
"""


import inspect
from time import sleep, time
from pathlib import Path
from typing import Callable
from typing import Union

import cv2
import keyboard
import numpy as np
import pytesseract
import uinput
import logging

from SCAutolib import run, logger, TEMPLATES_DIR
from SCAutolib.utils import isDistro
from SCAutolib.exceptions import SCAutolibGUIException, SCAutolibNotFound


class Screen:
    """
    Captures screenshots of the system's display.
    It manages the naming and numbering of screenshots and can integrate them
    into an HTML report.
    """
    def __init__(self, directory: str, html_file: str = None):
        """
        Initializes the ``Screen`` object, setting up the directory where
        screenshots will be saved and tracking the next screenshot number.
        Optionally links to an HTML file for report generation.

        :param directory: Path to the directory where the screenshots will be
                          saved.
        :type directory: str
        :param html_file: Path to an HTML file where image tags for screenshots
                          will be appended.
        :type html_file: str, optional
        :return: None
        :rtype: None
        """

        self.directory = directory
        self.html_file = html_file

        taken_images = [str(image).split('/')[-1]
                        for image in Path(directory).iterdir()]
        taken_image_ids = [int(image.split('.')[0]) for image in taken_images]
        taken_image_ids.sort(reverse=True)

        self.screenshot_num = 1
        if len(taken_images) > 0:
            self.screenshot_num = taken_image_ids[0] + 1

    def screenshot(self, timeout: float = 30):
        """
        Captures a screenshot of the display using the ``ffmpeg`` command with
        `kmsgrab` input. It repeatedly tries to capture
        until successful or a specified timeout is reached.
        The screenshot is saved as a PNG file and its path is returned.

        :param timeout: The maximum time in seconds to wait for ``ffmpeg`` to
                        successfully capture a screenshot.
        :type timeout: float
        :return: The string path to the captured screenshot file.
        :rtype: str
        :raises SCAutolibGUIException: If ``ffmpeg`` cannot capture a
                                       screenshot within the specified timeout
                                       period.
        """

        logger.debug(f"Taking screenshot number {self.screenshot_num}")

        filename = f'{self.directory}/{self.screenshot_num}.png'
        t_end = time() + timeout
        captured = False

        # if the ffmpeg command fails,
        # try screenshotting again until the timeout
        while time() < t_end and not captured:
            out = run(['ffmpeg', '-hide_banner', '-y', '-f',
                       'kmsgrab', '-i', '-', '-vf', 'hwdownload,format=bgr0',
                       '-frames', '1', '-update', '1',
                       filename], check=False, log=False)

            if out.returncode == 0:
                captured = True
            else:
                logger.debug(f"ffmpeg failed with {out.returncode}. "
                             f"stdout: {out.stdout}, stderr: {out.stderr}")

        if not captured:
            raise SCAutolibGUIException(
                'Could not capture screenshot within timeout.')

        if self.html_file:
            with open(self.html_file, 'a') as fp:
                fp.write(
                    f"<img src=\"screenshots/{self.screenshot_num}.png\" "
                    f"alt=\"screenshot number {self.screenshot_num}\">"
                )

        self.screenshot_num += 1
        return filename


class Mouse:
    """
    Controls the mouse cursor and clicks on the system under test using the
    ``uinput`` kernel module.
    """
    def __init__(self):
        """
        Initializes the ``Mouse`` object by loading the ``uinput`` kernel
        module and creating a virtual ``uinput`` device for mouse events.
        """

        run(['modprobe', 'uinput'], check=True)

        # Maximum coordinate for both axis
        self.ABS_MAX = 2**16

        # initialize the uinput device
        self.device = uinput.Device((
            uinput.ABS_X + (0, self.ABS_MAX, 0, 0),
            uinput.ABS_Y + (0, self.ABS_MAX, 0, 0),
            uinput.BTN_LEFT,
            uinput.BTN_MIDDLE,
            uinput.BTN_RIGHT,
            uinput.REL_WHEEL,
        ))

        self.CLICK_HOLD_TIME = 0.1

    def move(self, x: float, y: float):
        """
        Moves the mouse cursor to a specified absolute coordinate on the
        screen. Coordinates are provided as float numbers
        between 0 and 1, which are then mapped to the screen's resolution.

        :param x: The X-coordinate of the cursor, a float between 0 and 1
                  (inclusive).
        :type x: float
        :param y: The Y-coordinate of the cursor, a float between 0 and 1
                  (inclusive).
        :type y: float
        :return: None
        :rtype: None
        :raises ValueError: If either X or Y coordinate is not within the 0 to
                            1 range.
        """

        logger.info(f'Moving mouse to {x, y})')

        for uinput_axis, value in [(uinput.ABS_X, x), (uinput.ABS_Y, y)]:
            # Check if value between 0 and 1
            if not (0 <= value <= 1):
                raise ValueError("Values must be floats between 0 and 1")
            converted = int(value * self.ABS_MAX)
            self.device.emit(uinput_axis, converted, syn=False)

        # Both axes move at once
        self.device.syn()

    def click(self, button: str = 'left'):
        """
        Simulates a click of a specified mouse button.

        :param button: The mouse button to click. Possible values are ``left``,
                       ``right``, or ``middle``. Defaults to ``left``.
        :type button: str
        :return: None
        :rtype: None
        :raises KeyError: If button is not ``left``, ``right``, or ``middle``.
        """

        button_map = {
            'left': uinput.BTN_LEFT,
            'right': uinput.BTN_RIGHT,
            'middle': uinput.BTN_MIDDLE,
        }
        uinput_button = button_map[button]

        logger.info(f'Clicking the {button} mouse button')

        # press the button
        self.device.emit(uinput_button, 1)
        # wait a little
        sleep(self.CLICK_HOLD_TIME)
        # release the button
        self.device.emit(uinput_button, 0)


def image_to_data(path: str, threshold: int = 120):
    """
    Converts a screenshot image into a DataFrame of words with their
    normalized coordinates and dimensions. This process
    involves image preprocessing (grayscale, upscaling, binarization)
    and OCR (Optical Character Recognition) using `pytesseract`.

    :param path: The string path to the image file (screenshot) to convert.
    :type path: str
    :return: A DataFrame containing detected words, their bounding box
             coordinates, and other OCR-related data.
    """
    upscaling_factor = 2

    image = cv2.imread(path)
    grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    upscaled = cv2.resize(grayscale,
                          dsize=None,
                          fx=upscaling_factor,
                          fy=upscaling_factor,
                          interpolation=cv2.INTER_LANCZOS4)
    _, binary = cv2.threshold(upscaled, threshold, 255, cv2.THRESH_BINARY_INV)
    df = pytesseract.image_to_data(binary, output_type='data.frame')

    yres, xres = binary.shape[:2]
    df[['left', 'width']] /= xres
    df[['top', 'height']] /= yres

    logger.debug(df)
    return df


def images_equal(path1: str, path2: str):
    """
    Compares two images to determine if they are pixel-perfectly identical.
    Images are considered identical if they have the same
    resolution and all pixel values are exactly equal.

    :param path1: The string path to the first image file.
    :type path1: str
    :param path2: The string path to the second image file.
    :type path2: str
    :return: ``True`` if the images are identical; ``False`` otherwise.
    :rtype: bool
    """
    im1 = cv2.imread(path1)
    im2 = cv2.imread(path2)

    # Is the resolution the same
    if im1.shape != im2.shape:
        return False

    # Check if value of every pixel is the same
    if np.bitwise_xor(im1, im2).any():
        return False

    return True


def action_decorator(func: Callable):
    """
    A decorator for GUI automation functions that change the state of the GUI.
    This decorator captures a screenshot before and after
    the decorated function's execution. If both screenshots
    are identical and `check_difference` is enabled, an exception is raised,
    indicating that the action did not produce a visible change.

    :param func: The function to be decorated.
    :type func: callable
    :return: The wrapper function that adds pre- and post-action screenshot
             and comparison logic.
    :rtype: callable
    :raises SCAutolibGUIException: If `check_difference` is enabled and that
                                   the action did not produce a visible change
    """

    def wrapper(self,
                *args,
                wait_time: int = None,
                **kwargs):

        start_screenshot = self.screen.screenshot() if self.screenshot else None

        func(self, *args, **kwargs)

        sleep(wait_time or self.wait_time)

        end_screenshot = self.screen.screenshot() if self.screenshot else None

        if self.screenshot and self.check_difference:
            # the action should change contents of the screen
            if images_equal(start_screenshot, end_screenshot):
                # If the screenshot before and after action are the same
                # an exception is raised
                raise SCAutolibGUIException(
                    "Action did not change the contents of the screen")

    return wrapper


def log_decorator(func: Callable):
    """
    A decorator that logs the invocation of the decorated function, including
    its name and arguments. This provides a clear
    record of GUI actions being performed.

    :param func: The function to be decorated.
    :type func: callable
    :return: The wrapper function that adds logging functionality.
    :rtype: callable
    """

    def wrapper(self, *args, **kwargs):
        # Format the arguments for logging
        kwargs_list = ["=".join((key, repr(value)))
                       for key, value in kwargs.items()]
        args_list = [repr(value) for value in list(args[1:])]
        all_args = ", ".join(args_list + kwargs_list)
        logger.info(f'Calling GUI.{func.__name__}({all_args})')
        func(self, *args, **kwargs)
    return wrapper


class GUI:
    """
    Represents the Graphical User Interface (GUI) of the system under test
    and provides methods for controlling it. It integrates
    screenshot capture, mouse control, and keyboard input to automate GUI
    interactions and perform visual assertions.
    The class is designed to be used as a context manager for proper setup
    and cleanup of the GUI testing environment.
    """
    def __init__(self,
                 wait_time: float = 5,
                 res_dir_name: str = None,
                 from_cli: bool = False,
                 screenshot: bool = True,
                 check_difference: bool = True):
        """
        Initializes the GUI automation environment. This includes
        setting up directories for screenshots and HTML reports, configuring
        logging to file, and initializing mouse and screen control objects.

        :param wait_time: The default time in seconds to wait after each GUI
                          action to allow the system to respond.
        :type wait_time: float
        :param res_dir_name: An optional custom name for the results directory
                             under ``/tmp/SC-tests/``. If not provided, a
                             default name based on timestamp and caller
                             function name (or "cli_gui" for CLI runs) is used.
        :type res_dir_name: str, optional
        :param from_cli: A boolean flag indicating if the ``GUI`` instance is
                         being created from a CLI command. This affects
                         logging setup and directory naming.
        :type from_cli: bool
        :return: None
        :rtype: None
        """

        self.wait_time = wait_time
        self.gdm_init_time = 10
        self.from_cli = from_cli
        # Create the directory for screenshots
        self.html_directory = Path("/tmp/SC-tests")
        if not self.html_directory.exists():
            self.html_directory.mkdir()
        if res_dir_name:
            self.html_directory = self.html_directory.joinpath(res_dir_name)
        elif from_cli:
            run_dirs = [run_dir for run_dir in self.html_directory.iterdir()
                        if run_dir.is_dir() and "cli_gui" in run_dir.name]
            run_dirs.sort(key=lambda x: x.name, reverse=True)

            last_run_dir = run_dirs[0] if len(run_dirs) > 0 else None
            if last_run_dir and not last_run_dir.joinpath('.done').exists():
                # Use the old run directory
                logger.debug("Using HTML logging file from last time.")
                self.html_directory = self.html_directory.joinpath(
                    last_run_dir)
            else:
                # Create new run directory
                logger.debug("Creating new HTML logging file.")
                self.html_directory = self.html_directory.joinpath(
                    str(int(time())) + '_cli_gui')
        else:
            calling_func = inspect.stack()[1][3]
            self.html_directory = self.html_directory.joinpath(
                str(int(time())) + '_' + calling_func)

        self.screenshot_directory = self.html_directory.joinpath("screenshots")
        # will create both dirs
        self.screenshot_directory.mkdir(parents=True, exist_ok=True)

        # Code for image matching and asserting
        self.match_directory = self.html_directory.joinpath("image_matches")
        self.match_directory.mkdir(parents=True, exist_ok=True)

        taken_image_ids = [int(str(image).split('/')[-1].split('.')[0])
                           for image in Path(self.match_directory).iterdir()]

        match_num = 1
        if len(taken_image_ids) > 0:
            taken_image_ids.sort(reverse=True)
            match_num = taken_image_ids[0] + 1
        self.match_image_id = match_num

        self.html_file = self.html_directory.joinpath("index.html")
        if not self.html_file.exists():
            with open(self.html_file, 'w') as fp:
                fp.write(
                    "<html lang=\"en\">\n"
                    "<head>\n"
                    "<meta charset=\"UTF-8\">\n"
                    "<meta name=\"viewport\" content=\"width=device-width, "
                    "initial-scale=1.0\">\n"
                    "<title>Test Results</title>\n"
                    "</head>\n"
                    "<body style=\"background-color:#000;\">\n"
                )

        fmt = "<span style=\"color:limegreen;\">"
        fmt += "%(asctime)s</span> "
        fmt += "<span style=\"color:white;\">"
        fmt += "%(name)s:%(module)s.%(funcName)s.%(lineno)d </span>"
        fmt += "<span style=\"color:royalblue;\">[%(levelname)s] </span>"
        fmt += "<pre style=\"color:limegreen;\">%(message)s</pre>"
        self.fileHandler = logging.FileHandler(self.html_file)
        self.fileHandler.setLevel(logging.DEBUG)
        self.fileHandler.setFormatter(
            logging.Formatter("<p>" + fmt + "</p>")
        )

        if self.from_cli:
            logger.addHandler(self.fileHandler)

        self.mouse = Mouse()

        # workaround for keyboard library
        # otherwise the first character is not sent
        keyboard.send('enter')

        # create screen object to use from calls
        self.screen = Screen(self.screenshot_directory, self.html_file)

        # Set variables for screenshot and check_difference for
        # action_decorator
        self.screenshot = screenshot
        self.check_difference = check_difference

    def __enter__(self):
        """
        Enters the context manager for GUI testing.
        It restarts the GDM (GNOME Display Manager) service to ensure a defined
        system state and waits for it to initialize before GUI interactions
        begin. It also adds the file handler for logging
        if not initialized from CLI.

        :return: The ``GUI`` instance.
        :rtype: SCAutolib.models.gui.GUI
        """

        # By restarting gdm, the system gets into defined state
        run(['systemctl', 'restart', 'gdm'], check=True)
        # Cannot screenshot before gdm starts displaying
        # This would break the display
        sleep(self.gdm_init_time)

        if not self.from_cli:
            logger.addHandler(self.fileHandler)

        return self

    def __exit__(self, type, value, traceback):
        """
        Exits the context manager for GUI testing.
        It stops the GDM service to clean up the graphical environment and
        finalizes the HTML logging file.
        A "done" file is created in the results directory to indicate
        completion.

        :param type: The type of the exception that caused the context to be
                     exited, or ``None`` if no exception occurred.
        :param value: The exception instance that caused the context to be
                      exited, or ``None``.
        :param traceback: The traceback object associated with the exception,
                          or ``None``.
        :return: None
        :rtype: None
        """

        done_file = self.html_directory.joinpath('.done')
        if done_file.exists():
            return

        run(['systemctl', 'stop', 'gdm'], check=True)

        with open(self.html_file, 'a') as fp:
            fp.write(
                "</body>\n"
                "</html>\n"
            )

        with open(done_file, 'w') as fp:
            fp.write("done")

        if not self.from_cli:
            logger.removeHandler(self.fileHandler)

        logger.info(f"HTML file with results created in {self.html_directory}.")

    @action_decorator
    @log_decorator
    def click_on(self, key: str, timeout: float = 30,
                 min_thres: int = 120, max_thres: int = 160,
                 case_sensitive: bool = True,
                 click_on_match: int = 1):
        """
        Simulates a mouse click on a GUI object containing the specified text.
        It repeatedly captures screenshots and
        performs OCR to locate the text until it is found or a timeout is
        reached. Once found, the mouse cursor is moved to
        the center of the detected text and a click is performed.

        :param key: The string to find on the screenshot, identifying the
                    object to click.
        :type key: str
        :param timeout: The maximum time in seconds to wait for the ``key`` to
                        be found on the screen before raising an exception.
        :type timeout: float
        :param min_thres: The initial threshold that will be use in the
                          beginning for matching the words. Threshold would be
                          increasing to with every failed iteration to the
                          value of the max_thres value.
                          Default 120.
        :type min_thres: int
        :param max_thres: The maximum threshold on which the script will do to
                          match words.
                          Default 160.
        :type max_thres: int
        :param case_sensitive: if True then the case of the key must be matched
                               exactly, if False then the case is not relevant.
                               Default True.
        :type case_sensitive: bool
        :param click_on_match: if multiple matches are found then click on
                               the nth match.
                               Default 0 (first match)
        :type click_on_match: int
        :return: None
        :rtype: None
        :raises SCAutolibGUIException: If a parameter is not configured
                                       correctly.
        :raises SCAutolibNotFound: If the ``key`` is not found in screenshots
                                   within the specified timeout.
        """

        if click_on_match < 1:
            raise SCAutolibGUIException(
                "The match to click one should be more or equal to 1.")

        thres_diff = max_thres - min_thres
        if thres_diff < 0:
            raise SCAutolibGUIException(
                "Image max_thres cannot be smaller than min_thres.")

        if not case_sensitive:
            key = key.lower()

        logger.info(f"Trying to find key='{key}' to click on.")

        item = None
        first_scr = None
        last_scr = None

        key_list = key.split(" ")
        multiword = len(key_list) > 1

        start_time = time()
        end_time = start_time + timeout

        # Repeat screenshotting, until the key is found
        passed_time = time()
        while passed_time < end_time:
            # Capture the screenshot
            screenshot = self.screen.screenshot()

            last_scr = screenshot
            if first_scr is None:
                first_scr = screenshot

            threshold = int(
                min_thres + (
                    thres_diff * (int(passed_time - start_time) / timeout)
                )
            )
            df = image_to_data(screenshot, threshold=threshold)

            if not case_sensitive:
                df['text'] = df['text'].map(
                    lambda x: x.lower() if isinstance(x, str) else x)

            selection = None
            search_key = key
            if multiword:
                words = " ".join(str(text) for text in df['text'])
                if key in words:
                    search_key = key_list[0]

            selection = df['text'] == search_key

            # If there is no matching word, try again
            if selection is not None and selection.sum() == 0:
                logger.info('Found no match, trying again')
                passed_time = time()
                continue

            # Exactly one word matching, exit the loop
            elif selection.sum() == 1:
                logger.info('Found exactly one match')
                item = df[selection].iloc[0]
                break

            # More than one word matches, choose the first match
            # Probably deterministic, but it should not be relied upon
            else:
                logger.info('Found multiple matches. '
                            f'Clicking on match number {click_on_match}.')
                item = df[selection].iloc[click_on_match - 1]
                break

        if item is None:
            raise SCAutolibNotFound(
                f"Found no key='{key}' in screenshots "
                f"{first_scr} to {last_scr}")

        x = float(item['left'] + item['width'] / 2)
        y = float(item['top'] + item['height'] / 2)

        self.mouse.move(x, y)
        sleep(0.5)
        self.mouse.click()
        sleep(self.wait_time)

    @action_decorator
    @log_decorator
    def kb_write(self, *args, press_enter: bool = True, **kwargs):
        """
        Simulates typing a literal string of characters into the active GUI
        input field or window. It handles uppercase
        characters by sending a shift key press.

        :param args: Positional arguments. The first argument is expected to be
                     the string to write.
        :type args: tuple
        :param press_enter: If set (default), after the text the enter button
                            will be pressed.
        :type press_enter: bool
        :param kwargs: Additional keyword arguments are passed to
                       ``keyboard.write`` (e.g., ``delay``).
        :type kwargs: dict
        :return: None
        :rtype: None
        """
        # delay is a workaround needed for keyboard library
        kwargs.setdefault('delay', 0.1)

        # If screenshot is False, need a slight delay before sending to
        # keyboard.write() to workaround first key(char) being missed
        if not self.screenshot:
            sleep(0.1)

        word = args[0]
        last = ""
        for char in word:
            if char.isupper():
                if last != "":
                    keyboard.write(*[last], **kwargs)
                    last = ""
                keyboard.send(f"shift+{char.lower()}")
            else:
                last = f"{last}{char}"

        keyboard.write(*[last], **kwargs)

        if press_enter:
            self.kb_send('enter')

    @action_decorator
    @log_decorator
    def kb_send(self, *args, **kwargs):
        """
        Sends specific key(s) or key combinations to the keyboard.
        This method wraps the ``keyboard.send`` function.

        :param args: Positional arguments representing the key(s) to send
                     (e.g., ``enter``, ``alt+f4``).
        :type args: tuple
        :param kwargs: Additional keyword arguments passed directly to
                      ``keyboard.send``.
        :type kwargs: dict
        :return: None
        :rtype: None
        """
        # If screenshot is False, need a slight delay before sending to
        # keyboard.write() to workaround first key(char) being missed
        if not self.screenshot:
            sleep(0.1)

        keyboard.send(*args, **kwargs)

    @log_decorator
    def assert_text(self, key: str, timeout: float = 0,
                    min_thres: int = 120, max_thres: int = 160,
                    case_sensitive: bool = True, get_text: bool = False):
        """
        Asserts that a given text string (``key``) is found on the screen
        within a specified timeout. It repeatedly captures
        screenshots and performs OCR until the text is detected or the timeout
        expires.

        :param key: The string to find in the screenshots.
        :type key: str
        :param timeout: The maximum time in seconds to wait for the ``key`` to
                        be found. A zero timeout means only one screenshot
                        will be taken and evaluated.
        :type timeout: float
        :param min_thres: The initial threshold that will be use in the
                          beginning for matching the words. Threshold would be
                          increasing to with every failed iteration to the
                          value of the max_thres value.
                          Default 120.
        :type min_thres: int
        :param max_thres: The maximum threshold on which the script will do to
                          match words.
                          Default 160.
        :type max_thres: int
        :param case_sensitive: if True then the case of the key must be matched
                               exactly, if False then the case is not relevant.
                               Default True.
        :type case_sensitive: bool
        :param get_text: if True then the text found on the screen will be
                         output to the log.
                         Default False.
        :type get_text: bool
        :return: None
        :rtype: None
        :raises SCAutolibGUIException: If a parameter is not configured
                                       correctly.
        :raises SCAutolibNotFound: If the ``key`` is not found in any
                                   screenshot within the specified timeout.
        """

        logger.info(f"Trying to find key='{key}'")

        if not case_sensitive:
            key = key.lower()

        thres_diff = max_thres - min_thres
        if thres_diff < 0:
            raise SCAutolibGUIException(
                "Image max_thres cannot be smaller than min_thres.")

        key_list = key.split(" ")
        multiword = len(key_list) > 1
        threshold = max_thres

        start_time = time()
        end_time = start_time + timeout

        first = True
        passed_time = start_time
        while first or passed_time < end_time:
            first = False
            # Capture the screenshot
            screenshot = self.screen.screenshot()

            if timeout:
                threshold = int(
                    min_thres + (
                        thres_diff * (int(passed_time - start_time) / timeout)
                    )
                )
            df = image_to_data(screenshot, threshold=threshold)

            if not case_sensitive:
                df['text'] = df['text'].map(
                    lambda x: x.lower() if isinstance(x, str) else x)

            if get_text:
                text_dump = ["|"]
                for text in df['text']:
                    if type(text) is str:
                        text_dump.append(text)
                    elif type(text) is not str and text_dump[-1] != "|":
                        text_dump.append("|")
                text_dump.pop(0)
                logger.info(f"Text dump='{' '.join(text_dump)}'")

            selection = None
            if multiword:
                words = " ".join(str(text) for text in df['text'])
                if key in words:
                    selection = df['text'] == key_list[0]
            else:
                selection = df['text'] == key

            # The key was found
            if selection is not None and selection.sum() != 0:
                return

            passed_time = time()

        raise SCAutolibNotFound(f"The key='{key}' was not found.")

    @log_decorator
    def assert_no_text(self, key: str, timeout: float = 0,
                       min_thres: int = 120, max_thres: int = 160,
                       case_sensitive: bool = True):
        """
        Asserts that a given text string (`key`) is *not* found on the screen
        within a specified timeout. If the key is found in any screenshot
        during the monitoring period, an exception is raised.

        :param key: The string that should not be found in the screenshots.
        :type key: str
        :param timeout: The maximum time in seconds to monitor for the absence
                        of the ``key``. A zero timeout means only one
                        screenshot will be taken and evaluated.
        :type timeout: float
        :param min_thres: The initial threshold that will be use in the
                          beginning for matching the words. Threshold would be
                          increasing to with every failed iteration to the
                          value of the max_thres value.
                          Default 120.
        :type min_thres: int
        :param max_thres: The maximum threshold on which the script will do to
                          match words.
                          Default 160.
        :type max_thres: int
        :param case_sensitive: if True then the case of the key must be matched
                               exactly, if False then the case is not relevant.
                               Default True.
        :type case_sensitive: bool
        :return: None
        :rtype: None
        :raises SCAutolibGUIException: If a parameter is not configured
                                       correctly.
        :raises SCAutolibNotFound: If the ``key`` is found in any screenshot
                                   within the specified timeout.
        """

        logger.info(f"Trying to find key='{key}'"
                    " (it should not be in the screenshot)")

        if not case_sensitive:
            key = key.lower()

        thres_diff = max_thres - min_thres
        if thres_diff < 0:
            raise SCAutolibGUIException(
                "Image max_thres cannot be smaller than min_thres.")

        key_list = key.split(" ")
        multiword = len(key_list) > 1
        threshold = max_thres

        start_time = time()
        end_time = start_time + timeout

        first = True
        passed_time = start_time
        while first or passed_time < end_time:
            first = False
            # Capture the screenshot
            screenshot = self.screen.screenshot()

            if timeout:
                threshold = int(
                    min_thres + (
                        thres_diff * (int(passed_time - start_time) / timeout)
                    )
                )
            df = image_to_data(screenshot, threshold=threshold)

            if not case_sensitive:
                df['text'] = df['text'].map(
                    lambda x: x.lower() if isinstance(x, str) else x)

            selection = None
            if multiword:
                words = " ".join(str(text) for text in df['text'])
                if key in words:
                    raise SCAutolibNotFound(
                        f"The key='{key}' was found "
                        f"in the screenshot {screenshot}")
            else:
                selection = df['text'] == key

                # The key was found, but should not be
                if selection is not None and selection.sum() != 0:
                    raise SCAutolibNotFound(
                        f"The key='{key}' was found "
                        f"in the screenshot {screenshot}")

            passed_time = time()

    @log_decorator
    def assert_image(self, img_path: Union[str, Path], timeout: float = 0,
                     start_thres: float = .85, end_thres: float = .75):
        """
        Asserts that a given image (taken from a path) is found on the screen
        within a specified timeout. If the image is found in any screenshot
        during the monitoring period, an exception is raised.

        :param img_path: The path of the image that should be found in the
                         screenshots.
        :type img_path: str or Path
        :param timeout: The maximum time in seconds to monitor for the presence
                        of the image. A zero timeout means only one
                        screenshot will be taken and evaluated.
        :type timeout: float
        :param start_thres: The initial threshold that will be use in the
                            beginning for matching the image. Threshold would
                            be increasing to with every failed iteration to the
                            value of the end_thres value if timeout is
                            specified.
                            Default 0.85.
        :type start_thres: float
        :param end_thres: The final threshold on which the script will do to
                          match the image.
                          Default 0.80.
        :type end_thres: float
        :return: None
        :rtype: None
        :raises SCAutolibGUIException: If a parameter is not configured
                                       correctly.
        :raises SCAutolibNotFound: If the image is not found in any screenshot
                                   within the specified timeout.
        """

        logger.info(f"Trying to match image from '{img_path}'"
                    " (it should be in the screenshot)")

        thres_diff = start_thres - end_thres
        if thres_diff < 0:
            raise SCAutolibGUIException(
                "Image start_thres cannot be smaller than end_thres.")

        threshold = start_thres

        start_time = time()
        end_time = start_time + timeout

        image_found = False
        first = True
        passed_time = start_time
        while first or passed_time < end_time:
            first = False

            screenshot = self.screen.screenshot()
            img_rgb = cv2.imread(screenshot)
            template = cv2.imread(img_path)
            w, h = template.shape[:-1]

            res = cv2.matchTemplate(img_rgb, template, cv2.TM_CCOEFF_NORMED)
            if timeout:
                threshold = (
                    start_thres - (
                        thres_diff * (int(passed_time - start_time) / timeout)
                    )
                )
            logger.debug(f"Using threshold {threshold} for image matching.")
            loc = np.where(res >= threshold)
            for pt in zip(*loc[::-1]):  # Switch columns and rows
                image_found = True
                cv2.rectangle(
                    img_rgb, pt, (pt[0] + w, pt[1] + h), (0, 0, 255), 1)

            match_path = self.match_directory.joinpath(
                f"{self.match_image_id}.png")
            cv2.imwrite(match_path, img_rgb)
            logger.debug(f"Saved image with match number {self.match_image_id}.")

            if self.html_file:
                with open(self.html_file, 'a') as fp:
                    fp.write(
                        f"<img src=\"image_matches/{self.match_image_id}.png\" "
                        f"alt=\"Image match number {self.match_image_id}\">"
                    )

            self.match_image_id += 1

            if image_found:
                break

            passed_time = time()

        if not image_found:
            raise SCAutolibNotFound(f"Image from '{img_path}' was not found "
                                    f"in the screenshot {screenshot}. "
                                    f"Check {match_path}.")

    @log_decorator
    def assert_no_image(self, img_path: Union[str, Path], timeout: float = 0,
                        start_thres: float = .85, end_thres: float = .75):
        """
        Asserts that a given image (taken from a path) is *not* found on the
        screen within a specified timeout. If the image is found in any
        screenshot during the monitoring period, an exception is raised.

        :param img_path: The path of the image that should be found in the
                         screenshots.
        :type img_path: str or Path
        :param timeout: The maximum time in seconds to monitor for the presence
                        of the image. A zero timeout means only one
                        screenshot will be taken and evaluated.
        :type timeout: float
        :param start_thres: The initial threshold that will be use in the
                            beginning for matching the image. Threshold would
                            be increasing to with every failed iteration to the
                            value of the end_thres value if timeout is
                            specified.
                            Default 0.85.
        :type start_thres: float
        :param end_thres: The final threshold on which the script will do to
                          match the image.
                          Default 0.80.
        :type end_thres: float
        :return: None
        :rtype: None
        :raises SCAutolibGUIException: If a parameter is not configured
                                       correctly.
        :raises SCAutolibNotFound: If the image is not found in any screenshot
                                   within the specified timeout.
        """

        logger.info(f"Trying to match image from '{img_path}'"
                    " (it should not be in the screenshot)")

        thres_diff = start_thres - end_thres
        if thres_diff < 0:
            raise SCAutolibGUIException(
                "Image start_thres cannot be smaller than end_thres.")

        threshold = start_thres

        start_time = time()
        end_time = start_time + timeout

        image_found = False
        first = True
        passed_time = start_time
        while first or passed_time < end_time:
            first = False

            screenshot = self.screen.screenshot()
            img_rgb = cv2.imread(screenshot)
            template = cv2.imread(img_path)
            w, h = template.shape[:-1]

            res = cv2.matchTemplate(img_rgb, template, cv2.TM_CCOEFF_NORMED)
            if timeout:
                threshold = (
                    start_thres - (
                        thres_diff * (int(passed_time - start_time) / timeout)
                    )
                )
            logger.debug(f"Using threshold {threshold} for image matching.")
            loc = np.where(res >= threshold)
            for pt in zip(*loc[::-1]):  # Switch columns and rows
                image_found = True
                cv2.rectangle(
                    img_rgb, pt, (pt[0] + w, pt[1] + h), (0, 0, 255), 1)

            match_path = self.match_directory.joinpath(
                f"{self.match_image_id}.png")
            cv2.imwrite(match_path, img_rgb)
            logger.debug(f"Saved image with match number {self.match_image_id}.")

            if self.html_file:
                with open(self.html_file, 'a') as fp:
                    fp.write(
                        f"<img src=\"image_matches/{self.match_image_id}.png\" "
                        f"alt=\"Image match number {self.match_image_id}\">"
                    )

            self.match_image_id += 1

            if image_found:
                raise SCAutolibNotFound(f"Image from '{img_path}' was found "
                                        f"in the screenshot {screenshot}. "
                                        f"Check {match_path}.")

            passed_time = time()

    @log_decorator
    def check_home_screen(self, polarity: bool = True):
        """
        Checks for the presence or absence of a specific string on the screen
        to determine if the displayed GUI is the system's "home screen" or
        desktop. It adapts the text to search for based
        on the detected Linux distribution (e.g., "to search" for Fedora >= 42,
        "tosearch" for Fedora < 42, "Activities" for CentOS and RHEL).

        :param polarity: If ``True``, it asserts that the home screen indicator
                         text is present. If ``False``, it asserts that the
                         text is *not* present.
        :type polarity: bool
        :return: None
        :rtype: None
        :raises Exception: If the assertion (presence or absence of text) fails
                           within the timeout.
        """

        if isDistro('rhel', '>=10'):
            isImage = True
            func_str = ("assert_image"
                        if polarity is True else "assert_no_image")
        else:
            isImage = False
            func_str = ("assert_text"
                        if polarity is True else "assert_no_text")

        if isImage:
            arg = TEMPLATES_DIR.joinpath("match_for_RHEL-10.png")
        elif isDistro("fedora", ">=42"):
            arg = "to search"
        elif isDistro("fedora"):
            arg = "tosearch"
        else:
            arg = "Activities"

        func = getattr(self, func_str)
        func(arg, timeout=10)

import os
from time import sleep, time

import cv2
import keyboard
import numpy as np
import pytesseract
import uinput

from SCAutolib import run, logger


class Screen:
    """Captures the screenshots."""

    def __init__(self, directory: str):
        """Init method
        :param directory: Path to directory, where the screenshots
            will be saved.
        """
        self.directory = directory
        self.screenshot_num = 1

    def screenshot(self, timeout: float = 30):
        """Runs ffmpeg to take a screenshot.

        :param timeout: Timeout in seconds. If ffmpeg cannot take screenshot
            before the specified timeout, an exception is raised.
        :return: Path to the screenshot
        :rtype: str
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
                       filename], check=False, print_=False)

            if out.returncode == 0:
                captured = True

        if not captured:
            raise Exception('Could not capture screenshot within timeout.')

        self.screenshot_num += 1
        return filename


class Mouse:
    """Controls the mouse of the system under test
    """

    def __init__(self):
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
        """Moves the mouse cursor to specified absolute coordinate.
        Both coordinates are float numbers in range from 0 to 1.
        These get mapped to the screen resolution in the compositor.

        :param x: X coordinate of the cursor
        :param y: Y coordinate of the cursor
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
        """Clicks any button of the mouse.

        :param button: mouse button to click, defaults to 'left'
            Possible values 'left', 'right' or 'middle'.
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


def image_to_data(path: str):
    """Convert screenshot into dataframe of words with their coordinates.

    :param path: path to the image to convert.
    """
    upscaling_factor = 2

    image = cv2.imread(path)
    grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    upscaled = cv2.resize(grayscale,
                          dsize=None,
                          fx=upscaling_factor,
                          fy=upscaling_factor,
                          interpolation=cv2.INTER_LANCZOS4)
    _, binary = cv2.threshold(upscaled, 120, 255, cv2.THRESH_BINARY_INV)
    df = pytesseract.image_to_data(binary, output_type='data.frame')

    yres, xres = binary.shape[:2]
    df[['left', 'width']] /= xres
    df[['top', 'height']] /= yres

    logger.debug(df)
    return df


def images_equal(path1: str, path2: str):
    """Compare two images, return True if they are completely identical.
    Images are considered identical, when their resolutions match and
    all pixel values are equal.
    Images can be in any format, that can be read using
    imread function from OpenCV.

    :param path1: Path to the first image.
    :param path2: Path to the second image.
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


def action_decorator(func):
    """Decorator for all functions, that change the state of GUI.
    This decorator takes a screenshot before and after the action.
    The two screenshots are compared. If they are the same,
    an exception is raised.

    :param func: The function to be decorated
    """

    def wrapper(self,
                *args,
                wait_time=None,
                screenshot=True,
                check_difference=True,
                **kwargs):

        start_screenshot = self.screen.screenshot() if screenshot else None
        func(self, *args, **kwargs)
        sleep(wait_time or self.wait_time)
        end_screenshot = self.screen.screenshot() if screenshot else None

        if screenshot and check_difference:
            # If the checking is enabled
            # the action should change contents of the screen
            if images_equal(start_screenshot, end_screenshot):
                # If the screenshot before and after action are the same
                # an exception is raised
                raise Exception("Action did not change "
                                "the contents of the screen")

    return wrapper


def log_decorator(func):
    """Functions decorated with this will be logged when called.

    :param func: The function to be decorated
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
    """Represents the GUI and allows controlling the system under test."""

    def __init__(self, wait_time: float = 5):
        """Initializes the GUI of system under test.

        :param wait_time: Time to wait after each action
        """

        self.wait_time = wait_time
        self.gdm_init_time = 10
        # Create the directory for screenshots
        self.screenshot_directory = '/tmp/SC-tests/' + str(int(time()))
        os.makedirs(self.screenshot_directory, exist_ok=True)

        self.mouse = Mouse()

        # workaround for keyboard library
        # otherwise the first character is not sent
        keyboard.send('enter')

    def __enter__(self):
        self.screen = Screen(self.screenshot_directory)
        # By restarting gdm, the system gets into defined state
        run(['systemctl', 'restart', 'gdm'], check=True)
        # Cannot screenshot before gdm starts displaying
        # This would break the display
        sleep(self.gdm_init_time)

        return self

    def __exit__(self, type, value, traceback):
        run(['systemctl', 'stop', 'gdm'], check=True)

    @action_decorator
    @log_decorator
    def click_on(self, key: str, timeout: float = 30):
        """Clicks matching word on the screen.

        :param key: String to find in the screenshot.
        :param timeout: If the key is not found within this timeout,
            an exception will be raised. Timeout is in seconds.
        """
        logger.info(f"Trying to find key='{key}' to click on.")

        end_time = time() + timeout
        item = None
        first_scr = None
        last_scr = None

        # Repeat screenshotting, until the key is found
        while time() < end_time:
            # Capture the screenshot
            screenshot = self.screen.screenshot()

            last_scr = screenshot
            if first_scr is None:
                first_scr = screenshot

            df = image_to_data(screenshot)
            selection = df['text'] == key

            # If there is no matching word, try again
            if selection.sum() == 0:
                logger.info('Found no match, trying again')
                continue

            # Exactly one word matching, exit the loop
            elif selection.sum() == 1:
                logger.info('Found exactly one match')
                item = df[selection].iloc[0]
                break

            # More than one word matches, choose the first match
            # Probably deterministic, but it should not be relied upon
            else:
                logger.info('Found multiple matches')
                item = df[selection].iloc[0]
                break

        if item is None:
            raise Exception(f"Found no key='{key}' in screenshots "
                            f"{first_scr} to {last_scr}")

        x = float(item['left'] + item['width'] / 2)
        y = float(item['top'] + item['height'] / 2)

        self.mouse.move(x, y)
        sleep(0.5)
        self.mouse.click()
        sleep(self.wait_time)

    @action_decorator
    @log_decorator
    def kb_write(self, *args, **kwargs):
        # delay is a workaround needed for keyboard library
        kwargs.setdefault('delay', 0.1)
        keyboard.write(*args, **kwargs)

    @action_decorator
    @log_decorator
    def kb_send(self, *args, **kwargs):
        keyboard.send(*args, **kwargs)

    @log_decorator
    def assert_text(self, key: str, timeout: float = 0):
        """
        Given key must be found in a screenshot before the timeout.

        If the key is not found, exception is raised.
        Zero timeout means that only one screenshot
        will be taken and evaluated.

        :param key: String to find in the screenshot.
        :param timeout: If the key is not found within this timeout,
            an exception will be raised. Timeout is in seconds.
        """

        logger.info(f"Trying to find key='{key}'")

        end_time = time() + timeout
        first = True

        while first or time() < end_time:
            first = False
            # Capture the screenshot
            screenshot = self.screen.screenshot()
            df = image_to_data(screenshot)
            selection = df['text'] == key

            # The key was found
            if selection.sum() != 0:
                return

        raise Exception('The key was not found.')

    @log_decorator
    def assert_no_text(self, key: str, timeout: float = 0):
        """
        If the given key is found in any screenshot before the timeout,
        an exception is raised.

        Zero timeout means that only one screenshot
        will be taken and evaluated.

        :param key: String that should not be found in the screenshot.
        :param timeout: Timeout is in seconds.
        """
        logger.info(f"Trying to find key='{key}'"
                    " (it should not be in the screenshot)")

        end_time = time() + timeout
        first = True

        while first or time() < end_time:
            first = False
            # Capture the screenshot
            screenshot = self.screen.screenshot()
            df = image_to_data(screenshot)
            selection = df['text'] == key

            # The key was found, but should not be
            if selection.sum() != 0:
                raise Exception(f"The key='{key}' was found "
                                f"in the screenshot {screenshot}")

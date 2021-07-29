# Smart Card Automation library (SCAutolib)
Test automation library for Smart Cards.

> ⚠️ This library is in developmnet phase. There is nothing 100% stable.

This library is designed to run on RPM-based Linux destributions like RHEL 8, CentOS 8, Fedora 32 
(or newer versions of mentioned destributions, backwords compatibility is not implemented).

## Testine environment

To setup necessary environmnt for this library you would need at virtual smart
card in form of systemd service `virt_cacard.service`.
This setup can be done automatical with ansible playbook [main.yml](src/env/main.yml).
This playbook would setup local CA on a given host in [hosts](src/env/hosts) file.
Run this playbook with `ansible-playbook -i hosts main.yml`
After playbook end, you can check if virtual smart card is setup by cheking service status
`systemctl restart virt_cacard && systemctl status virt_cacard`.


## To Be Done

If you want to partisipate, there is a list of features that we would want to add to this library.
Fill free to suggest your solution or to suggest something more that you would like to have in this library.
Prioritized from top to bottom:

1. Kerberos integration
   - Setup Kerberos server with created local CA
   - Setup Kerberos client with previously created Kerberos server
2. GUI testing
   - To integrate OpenQA framework for testing GDM, Firefox, TTY, and other
3. DogTag integration
   - Setup DogTag to generate user certitifacates
   - Upload certitifacetes from DogTag on virtual smart card
   - Setup Kerberos server with DogTag server

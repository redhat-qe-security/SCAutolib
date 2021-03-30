# Smart Card Automation Library (SCAutolLib)
Test automation library for Smart Cards

## Startup guied

To setup necessary environmnt for this library you would need at virtual smart
card in form of systemd service __virt_cacard.service__.
This setup can be done automatical with ansible playbook [main.yml](src/env/main.yml).
This playbook would setup local CA on a given host in [hosts](src/env/hosts) file.
Run this playbook with `ansible-playbook -i hosts main.yml`
After playbook end, you can check if virtual smart card is setup by cheking service status
`systemctl restart virt_cacard && systemctl status virt_cacard`.

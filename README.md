# Smart Card Automation Library (SCAutolLib)
Test automation library for Smart Cards

## Startup guied

To setup necessary environmnt for this library you would need at virtual smart
card in form of systemd service __virt_cacard.service__.
This setup can be done automatical with ansible playbook [main.yml](src/env/main.yml).
This playbook would setup local CA and virtual smart card on a given host in [hosts](src/env/hosts) file.
After setting up required services, all test would be executed.
Run this playbook with `ansible-playbook -i hosts main.yml`

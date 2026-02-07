# Secrets management
Create a system which uses Apple's Secure Enclave and Passwords.app to store secrets and which has integration for sudo access from the terminal.

## Features
### CLI tool
A CLI tool to get and write secrets from passwords.app

### Generating SSH and AGE keys

A method to generate SSH keys and AGE keys which would be stored in Secure Enclave so that they can't be exported

### Integration with sudo

Integration with sudo to allow us to use touch id to allow access to sudo.


## Problems in the current tools

### Bad observability in touch id sudo integration
MacOS has the default integration for sudo and touch id by enabling:

```
auth sufficient pam_tid.so
```

But the problem is that the the popup window that appears doesn't really show anything else than sudo trying to get access:

![sudo asking for permissions with touch id](<Screenshot 2026-02-02 at 09.15.30 1.png>)

Instead of this I would want to see the full command and where it is coming from. What is the parent process?

### apw
apw is written with typescript instead of swift. It gets the job done but it doesn't integrate into the touch id. So now when I give the access code to integrate into apw it has free access to anything in my passwords.app. I would like to have a system which uses touch id to authenticate the access to secrets. It should say that which process is asking to access what password and then I could review that and allow it with my touch id. If I don't allow it then it should not be possible to access the secret.

### Secretive vs Age Secure Enclave
Secretive is amazing but it only has SSH keys. For example for SOPS integration we would need to be able to have AGE keys as well.

### Age Secure Enclave
This tool has the touch id integration but has again poor observability.

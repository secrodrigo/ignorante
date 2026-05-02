
   _                               _        
  (_) __ _ _ _  ___  _ _ __ _ _ _ | |_  ___ 
  | |/ _` | ' \/ _ \| '_/ _` | ' \|  _|/ -_)
  |_|\__, |_||_\___/|_| \__,_|_||_|\__|\___|
     |___/                                  


utility tool :)

[>] minimalist reverse shell listener

[>] automatic tty upgrade

[>] machine reconnaissance

### about

this is a utility tool for ctf mostly used on htb. i will update this tool as i feel like i need stuff to automate to make the process faster.

### usage

```bash
python3 ignorante.py rs <port>
```

### technical

- **listener:** opens a raw tcp socket to catch incoming connections.
- **tty upgrade:** probes for python/python3 on the target and spawns a pty shell for better interaction.
- **recon:** automatically executes initial commands (`uname`, `id`, `whoami`, `ls`) to gather environment context.
- **shell:** creates a threaded interaction loop for stable communication with the remote host.

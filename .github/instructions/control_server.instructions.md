---
applyTo: "control_server/**"
---

- Local control server infrastructure should be managed and tested solely with `pm2` process manager
- Local Logs should not be written to disk when working with `pm2`, as they can be fetched via for example `pm2 logs --lines 50 --nostream`
- Envs are located in `secrets/*`, find the correct env to fetch and add new data to respective to environment and logic
- Prefer working from project root, running commands, Makefile, and scripts from there, if it makes sense
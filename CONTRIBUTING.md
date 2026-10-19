# Contributing to Malworn

## Workflow

1. Pull the latest `main`:
   ```bash
   git checkout main
   git pull
   ```
2. Create a branch for your task:
   ```bash
   git checkout -b ahmed/pe-header-parser
   ```
   Name it `yourname/short-task-description`.
3. Commit as you work, with clear messages (`Add section entropy extraction`, not `update`).
4. Push your branch and open a pull request on GitHub:
   ```bash
   git push -u origin ahmed/pe-header-parser
   ```
5. One teammate reviews and approves, then merge.
6. Delete the branch after merging.

## Rules

- **Never commit malware samples, datasets, or model weights.** If `git status` shows one, stop and ask.
- **Never commit `.env`** or API keys. Use `.env.example` to show which variables exist.
- Stay in your own module folder unless the change has been agreed with the folder's owner.
- Keep pull requests small — one task per PR is easier to review.
- If you add a library, add it to `requirements.txt` in the same PR.

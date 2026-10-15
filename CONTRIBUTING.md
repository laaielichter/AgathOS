# Contributing to AgathOS

Thanks for helping. Small, clear changes are the easiest to review.

## Ways to help
- **Try it and report.** Open an issue with what you saw, what you expected, your system (Windows or macOS and the version) and, if you can, a screenshot. Mac testers are especially welcome.
- **Translations.** Native speakers: corrections are very welcome. The texts live in `src/locales/<code>.more.js`.
- **A missed danger.** Describe the attack or the file that AgathOS did not notice. Never post real keys or private files.
- **Code.** Pick an issue labelled `good first issue`, or open one to talk first.

## Working on the code
1. Install Node.js LTS, then `npm install` and `npm start` to run it.
2. Run `node test/run-tests.js`. Everything must pass before you open a pull request.
3. New texts for the window go in all 20 languages.
4. One change per pull request, described in plain English.

## Security problems
Please do not open a public issue. See [SECURITY.md](SECURITY.md).

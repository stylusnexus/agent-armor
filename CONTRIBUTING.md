# Contributing to Agent Armor

Thanks for your interest in making AI agents safer. Here's how to get started.

## Prerequisites

- Node.js >= 18
- npm
- Python 3.11+ (only if working on the ML pipeline)

## Setup

```bash
git clone https://github.com/anthropics/agent-armor.git
cd agent-armor
npm install
npm run build
npm run test:run
```

## Development Workflow

- Create a feature branch from `main` (`git checkout -b feat/my-feature`)
- Make your changes
- Open a PR against `main`
- Use conventional commit messages (see below)

## Adding New Patterns

- Edit `src/patterns/default-patterns.ts`
- Run the eval suite to verify no regressions: `npx tsx scripts/eval/run-eval.ts`
- Include both adversarial and benign test cases when relevant

## Adding Eval Samples

- Edit `scripts/eval/samples.ts`
- Include both adversarial and benign cases
- Each sample needs a clear label and expected detection result

## Adding Detectors

- Implement the `Detector` interface defined in `src/types/index.ts`
- Register your detector in `AgentArmor`
- Add unit tests and eval samples covering your detector

## Code Style

- TypeScript strict mode
- Prettier for formatting
- No unnecessary dependencies
- Keep imports explicit

## Testing

- **Unit tests:** `npm run test:run`
- **Eval suite:** `npx tsx scripts/eval/run-eval.ts`

Run both before submitting a PR.

## ML Pipeline (Optional)

For contributors working on the ML-based detectors:

```bash
pip install -r requirements-ml.txt
```

- Training data generation scripts live in `ml/`
- See `ml/` for model training and export workflows

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` -- new feature
- `fix:` -- bug fix
- `docs:` -- documentation only
- `chore:` -- maintenance, deps, CI
- `feat!:` -- breaking change

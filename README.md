## Live Deployment

You can view the deployed app here: [Aurify](https://aurify-chi.vercel.app/)

## Tech Stack (Aurify)

When the app is finished, Aurify will use:

- **Frontend:** React, Vite, TypeScript, shadcn-ui, Tailwind CSS
- **State Management:** React Context, custom hooks
- **Authentication:** Firebase Auth (or similar)
- **AI Services:** Google Gemini API, custom feedback services
- **Backend (optional):** Firebase, or custom Node.js/Express server (if needed)
- **Deployment:** Vercel (recommended), Netlify, or similar
- **Testing:** Jest, React Testing Library (if added)
- **CI/CD:** GitHub Actions (optional)

This stack is modern, scalable, and easy for contributors to work with.
## Intern Onboarding & Contribution Tutorial

To ensure code quality and prevent accidental changes to the main repository, all interns should work on their own forks. Here’s how to get started:

### 1. Fork the Repository

Go to the main Aurify repo (e.g., https://github.com/Aurify-AI/Aurify) and click the "Fork" button at the top right. This will create a personal copy of the repo under your GitHub account.

### 2. Clone Your Fork

Copy the URL of your fork (e.g., https://github.com/<your-username>/Aurify.git) and run:
```sh
git clone https://github.com/<your-username>/Aurify.git
cd Aurify
```

### 3. Set Up the Project

Follow the setup instructions in the README to install dependencies and run the project locally.

### 4. Make Changes on a Branch

Create a new branch for each feature or fix:
```sh
git checkout -b feature/my-feature
```
Make your changes and commit them:
```sh
git add .
git commit -m "Describe your changes"
```

### 5. Push Changes to Your Fork

```sh
git push origin feature/my-feature
```

### 6. Open a Pull Request

Go to your fork on GitHub, and you’ll see a “Compare & pull request” button. Click it to open a PR against the main Aurify repo. Add a clear description of your changes.

### 7. Review & Merge

Your PR will be reviewed by a maintainer. Once approved, it will be merged into the main repo.

---

**Best Practices:**
- Always work on a branch, never on `main`.
- Keep your fork up to date by syncing with the upstream repo regularly.
- Ask questions and request reviews if you’re unsure about anything.

This workflow keeps the main repo safe and ensures everyone’s work is reviewed before merging.
# Aurify

Aurify is a modern web application designed to help users practice, learn, and engage with AI-powered feedback and community features. Built with React, Vite, TypeScript, shadcn-ui, and Tailwind CSS, Aurify offers a sleek, interactive experience for users interested in language learning, productivity, or other AI-driven tasks.

## What does Aurify do?

Aurify provides:
- AI-powered feedback and suggestions (using Google Gemini and other services)
- Community features for sharing and tracking progress
- Practice sessions and history tracking
- Authentication and user profiles
- Responsive design for mobile and desktop

## How to run Aurify after you fork

After forking the repository, follow these steps to get Aurify running locally:

1. **Clone your fork**
	```sh
	git clone <YOUR_FORK_URL>
	cd aurify
	```
2. **Install dependencies**
	```sh
	npm install
	```
3. **Set up environment variables**
	- If you plan to use Firebase or AI services, create a `.env` file in the root directory and add your API keys and config. Example:
	  ```env
	  VITE_FIREBASE_API_KEY=your_firebase_api_key
	  VITE_GEMINI_API_KEY=your_gemini_api_key
	  ```
	- Check `src/lib/firebase.ts` and `src/services/ai/geminiService.ts` for required variables.
4. **Start the development server**
	```sh
	npm run dev
	```
	The app will be available at `http://localhost:5173` (or as shown in your terminal).

## Technologies Used

Aurify is built with:
- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## Deployment

You can deploy Aurify using Vercel, Netlify, or any static hosting provider. 

## How can I edit this code?

There are several ways of editing your application.

**Use your preferred IDE**

If you want to work locally using your own IDE, you can clone this repo and push changes. 

The only requirement is having Node.js & npm installed - [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating)

Follow these steps:

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS


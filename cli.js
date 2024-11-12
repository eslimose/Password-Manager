import readline from 'readline';
import PasswordManager from './password-manager.js'; // Updated to use .js extension

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Helper function to prompt input
function promptInput(query) {
    return new Promise((resolve) => rl.question(query, resolve));
}

// Set a password flow
async function setPasswordFlow(passwordManager) {
    const domain = await promptInput('Enter domain: ');
    const storedPassword = await promptInput('Enter password: ');
    await passwordManager.set(domain, storedPassword);
    console.log('Password set successfully\n');
    promptUser(passwordManager);
}

// Get a password flow
async function getPasswordFlow(passwordManager) {
    const domain = await promptInput('Enter domain: ');
    const retrievedPassword = await passwordManager.get(domain);
    console.log(`Retrieved password: ${retrievedPassword || 'No password found'}\n`);
    promptUser(passwordManager);
}

// Remove a password flow
async function removePasswordFlow(passwordManager) {
    const domain = await promptInput('Enter domain: ');
    const success = await passwordManager.remove(domain);
    console.log(success ? 'Password removed successfully\n' : 'No password found\n');
    promptUser(passwordManager);
}

// Dump database flow
async function dumpDatabaseFlow(passwordManager) {
    // Since we're using a KVS, we'll show all stored passwords instead of dumping the entire database
    const allPasswords = passwordManager.db.get('passwords').value();
    console.log('Stored passwords:');
    allPasswords.forEach(password => {
        console.log(`Domain: ${password.name}, Value: ${password.value}`);
    });
    console.log('\n');
    promptUser(passwordManager);
}

// Load database flow
async function loadDatabaseFlow(passwordManager) {
    console.log("Database load functionality is not implemented for KVS here.\n");
    promptUser(passwordManager);
}

// Main function to prompt the user for an action
async function promptUser(passwordManager) {
    console.log('\nChoose an action:');
    console.log('1: Set a password');
    console.log('2: Get a password');
    console.log('3: Remove a password');
    console.log('4: Dump the database');
    console.log('5: Load the database');
    console.log('6: Exit\n');

    const option = await promptInput('Select an option: ');
    switch (option) {
        case '1':
            await setPasswordFlow(passwordManager);
            break;
        case '2':
            await getPasswordFlow(passwordManager);
            break;
        case '3':
            await removePasswordFlow(passwordManager);
            break;
        case '4':
            await dumpDatabaseFlow(passwordManager);
            break;
        case '5':
            await loadDatabaseFlow(passwordManager);
            break;
        case '6':
            console.log('Exiting...');
            rl.close();
            break;
        default:
            console.log('Invalid option, please try again.\n');
            promptUser(passwordManager);
            break;
    }
}

// Main entry point to initialize the password manager and start the application
async function startApp() {
    const masterPassword = await promptInput('Enter master password: ');

    // Initialize the password manager with the master password
    const passwordManager = await PasswordManager.init(masterPassword);

    // Start the application
    promptUser(passwordManager);
}

// Start the application
startApp();

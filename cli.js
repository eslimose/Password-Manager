const readline = require('readline');
const PasswordManager = require('./password-manager');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const passwordManager = new PasswordManager();

function promptUser() {
    rl.question('Enter master password: ', async (masterPassword) => {
        console.log('\nChoose an action:');
        console.log('1: Set a password');
        console.log('2: Get a password');
        console.log('3: Remove a password');
        console.log('4: Dump the database');
        console.log('5: Load the database');
        console.log('6: Exit\n');

        rl.question('Select an option: ', async (option) => {
            if (option === '1') {
                rl.question('Enter domain: ', async (domain) => {
                    rl.question('Enter password: ', async (storedPassword) => {
                        await passwordManager.set(masterPassword, domain, storedPassword);
                        console.log('Password set successfully\n');
                        promptUser();
                    });
                });
            } else if (option === '2') {
                rl.question('Enter domain: ', async (domain) => {
                    const retrievedPassword = await passwordManager.get(masterPassword, domain);
                    console.log(`Retrieved password: ${retrievedPassword || 'No password found'}\n`);
                    promptUser();
                });
            } else if (option === '3') {
                rl.question('Enter domain: ', async (domain) => {
                    const success = await passwordManager.remove(masterPassword, domain);
                    console.log(success ? 'Password removed successfully\n' : 'No password found\n');
                    promptUser();
                });
            } else if (option === '4') {
                const [dumpContents, checksum] = await passwordManager.dump();
                console.log(`Database dump: ${dumpContents}`);
                console.log(`Checksum: ${checksum}\n`);
                promptUser();
            } else if (option === '5') {
                rl.question('Enter dump contents: ', async (dumpContents) => {
                    rl.question('Enter checksum: ', async (checksum) => {
                        const success = await passwordManager.load(masterPassword, dumpContents, checksum);
                        console.log(success ? 'Database loaded successfully\n' : 'Failed to load database\n');
                        promptUser();
                    });
                });
            } else if (option === '6') {
                console.log('Exiting...');
                rl.close();
            } else {
                console.log('Invalid option, please try again.\n');
                promptUser();
            }
        });
    });
}

promptUser();
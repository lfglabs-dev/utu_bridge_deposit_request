# Utu Backend

This repository hosts the backend of Utu bridge

## Running the Application

1. Obtain the `.env.keys` file or update the `.env` file with necessary configurations.
2. Run the following command to start both the Telegram bot and the REST server:
   ```
   dotenvx run -- cargo run
   ```
   Or for production:
   ```
   dotenvx run -f .env.production -- cargo run
   ```

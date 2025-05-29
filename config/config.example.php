<?php
// config.php – Project configuration and constants
// Adjust values to your environment

return [

    // This project version
    'VERSION' => '0.1.1',

    // Your Database connection parameters
    'DB_HOST'           => '127.0.0.1',      // MySQL host
    'DB_NAME'           => 'your-db-name',   // Database name
    'DB_USER'           => 'your-user-name', // Database user
    'DB_PASS'           => 'your-password',  // Database password

    // Your JWT secret for signing tokens
    'JWT_SECRET'        => 'your-jwt-secret',

    // Your RustDesk Server Key from id_ed25519.pub
    'RD_PUBLIC_KEY'     => 'your-rd-public-key',
];

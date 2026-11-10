/**
 * ============================================================
 * app.js
 * ============================================================
 *
 * Main entry point for the Healthcare Observer
 * Threshold Cryptography system.
 *
 * ============================================================
 */

require("dotenv").config();

const config =
    require("./config");


console.log(
    "\n============================================================"
);

console.log(
    " HEALTHCARE OBSERVER + THRESHOLD CRYPTOGRAPHY"
);

console.log(
    "============================================================"
);


console.log(
    "\nSystem Configuration"
);

console.log(
    "------------------------------------------------------------"
);


console.log(
    "Chain X:",
    config.chainX.url
);


console.log(
    "Chain Y:",
    config.chainY.url
);


console.log(
    "Observers:",
    config.observers.total
);


console.log(
    "Minimum threshold:",
    config.observers.minThreshold
);


console.log(
    "Environment:",
    config.environment
);


console.log(
    "\n============================================================"
);

console.log(
    "Run the complete experiment using:"
);

console.log(
    "    npm run demo"
);

console.log(
    "============================================================\n"
);
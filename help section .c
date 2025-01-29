void help_menu() {
    clear_console();
    printf(BOLD ROYAL_BLUE "+---------------------------------------------+\n" RESET);
    printf(BOLD ROYAL_BLUE "|              HELP MENU                     |\n" RESET);
    printf(BOLD ROYAL_BLUE "+---------------------------------------------+\n" RESET);
    printf(ROYAL_BLUE "1. Encrypt: Encrypt data using AES encryption.\n" RESET);
    printf(ROYAL_BLUE "2. Decrypt: Decrypt AES-encrypted data.\n" RESET);
    printf(ROYAL_BLUE "3. Brute Force: Attempt to brute force a password.\n" RESET);
    printf(ROYAL_BLUE "4. View Logs: View tool usage and incident logs.\n" RESET);
    printf(ROYAL_BLUE "5. Exit: Exit the program.\n" RESET);
    printf(ROYAL_BLUE "6. Help: Show this help menu.\n" RESET);
    printf(ROYAL_BLUE "7. About: View project details.\n" RESET);
    printf(ROYAL_BLUE "Choose an option from the menu and follow the instructions.\n" RESET);
    sleep(3);  // Wait for a few seconds before returning to the main menu
}

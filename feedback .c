void log_incident_to_file(Incident incident) {
    pthread_mutex_lock(&file_mutex);
    FILE *fp = fopen("incidents.csv", "a");
    if (fp == NULL) {
        perror("Failed to open log file");
        pthread_mutex_unlock(&file_mutex);
        return;
    }
    char time_str[26];
    struct tm *tm_info = localtime(&incident.timestamp);
    strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(fp, "%d,%d,%s,%s,%s,%s\n",
            incident.type,
            incident.type,
            incident.source_ip,
            incident.dest_ip,
            incident.description,
            time_str);
    fclose(fp);
    pthread_mutex_unlock(&file_mutex);
    printf(ROYAL_BLUE "Incident logged successfully.\n" RESET);
}

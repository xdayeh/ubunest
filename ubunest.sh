#!/bin/bash

# ubunest - Ubuntu Server Setup Script (Enhanced)

# ==================== Configuration ====================
LOG_FILE="/var/log/ubunest.log"
FORCE_MODE=0
AUTO_CONTINUE=0

# Parse Arguments
for arg in "$@"; do
    case "$arg" in
        --force) FORCE_MODE=1 ;;
        --yes) AUTO_CONTINUE=1 ;;
    esac
done

# ==================== Functions ====================

# Ensure script is run as root and /tmp directory exists with correct permissions
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root." >&2
    exit 1
fi
if [[ ! -d /tmp ]]; then
    echo "[*] /tmp directory not found. Creating it with permissions 1777."
    mkdir -p /tmp
    chmod 1777 /tmp
else
    echo "[*] /tmp directory exists."
fi

# Timestamped logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}
generate_password() {
    < /dev/urandom tr -dc 'A-Za-z0-9@#$%&*' | head -c16
}
# Wait for APT/Dpkg to be free
wait_for_apt_with_timeout() {
    local timeout=60
    local waited=0
    local lock_files="/var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"

    log_message "Checking for active apt/dpkg operations..."

    while fuser $lock_files >/dev/null 2>&1; do
        if [[ $FORCE_MODE -eq 1 ]]; then
            log_message "Force mode enabled. Killing apt lock holders..."
            lsof $lock_files 2>/dev/null | awk 'NR>1 {print $2}' | sort -u | xargs -r kill -9
            break
        fi

        if [[ $waited -ge $timeout ]]; then
            log_message "APT appears to be locked for too long."
            echo "Processes holding locks:"
            lsof $lock_files 2>/dev/null | awk 'NR>1 {print $2}' | sort -u | xargs -r ps -p | tee -a "$LOG_FILE"

            if [[ $AUTO_CONTINUE -eq 1 ]]; then
                log_message "Auto mode enabled: bypassing lock after timeout."
                break
            fi

            echo "Do you want to kill the processes and continue? (y/n)"
            read -r choice
            if [[ "$choice" == "y" ]]; then
                lsof $lock_files 2>/dev/null | awk 'NR>1 {print $2}' | sort -u | xargs -r kill -9
                break
            else
                log_message "User aborted due to long lock."
                exit 1
            fi
        fi

        waited=$((waited + 5))
        log_message "Waiting for apt lock to be released... (${waited} sec)"
        sleep 5
    done

    log_message "APT lock released or bypassed. Proceeding..."
}

# Run a command with logging and optional continuation
run_cmd() {
    local description="$1"
    local cmd="$2"

    log_message "$description"
    log_message "Running command: $cmd"

    bash -c "$cmd" 2>&1 | while IFS= read -r line; do
        log_message "$line"
    done

    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        log_message "[ERROR] Command failed: $cmd"
        echo "There is an unexpected error. Please check the logs: $cmd"

        if [[ $AUTO_CONTINUE -eq 1 ]]; then
            log_message "Auto mode: continuing despite the error."
            return
        fi

        echo "Do you want to continue? (y/n)"
        read -r choice
        if [[ "$choice" != "y" ]]; then
            log_message "User chose to stop the script."
            exit 1
        fi
    fi
}
# Update and clean the system
update_system() {
    log_message "===== Step 1: System Update and Cleanup ====="

    wait_for_apt_with_timeout

    run_cmd "Start Updating Package Lists" "apt-get update -y"
    run_cmd "Start Upgrading Installed Packages" "apt-get upgrade -y"
    run_cmd "Start Distribution Upgrade" "apt-get dist-upgrade -y"

    log_message "System update and cleanup completed successfully."
}
install_web_stack() {
    log_message "===== Step 2: Installing LAMP Stack (Apache2, MySQL, PHP) ====="

    wait_for_apt_with_timeout

    run_cmd "Installing Apache2 and MySQL Server" "apt-get install apache2 mysql-server -y"
    run_cmd "Installing PHP and related modules" "apt-get install php libapache2-mod-php php-mysql -y"

    log_message "LAMP stack installation completed."
}
secure_mysql_manual() {
    log_message "===== Step 3: Securing MySQL Installation (Manual Alternative) ====="

    mysql -e "DELETE FROM mysql.user WHERE User='';" && \
    log_message "Anonymous users removed."

    mysql -e "UPDATE mysql.user SET Host='localhost' WHERE User='root';" && \
    log_message "Root remote login disabled."

    mysql -e "DROP DATABASE IF EXISTS test;" && \
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" && \
    log_message "Test database and access removed."

    mysql -e "FLUSH PRIVILEGES;" && \
    log_message "Privileges reloaded."

    log_message "MySQL secured successfully (manual method)."
}
ensure_apache_servername() {
    local apache_conf="/etc/apache2/apache2.conf"
    if ! grep -q "^ServerName" "$apache_conf"; then
        log_message "Global ServerName directive not found. Adding 'ServerName localhost' to $apache_conf"
        echo -e "\nServerName localhost" >> "$apache_conf"
    else
        log_message "Global ServerName directive already set."
    fi
}
reload_apache_safe() {
    log_message "Running apache2ctl configtest..."
    if ! apache2ctl configtest >/dev/null 2>&1; then
        log_message "[ERROR] Apache configtest failed. Aborting restart."
        return 1
    fi

    log_message "Reloading Apache service..."
    systemctl reload apache2
    if [[ $? -ne 0 ]]; then
        log_message "[ERROR] Failed to reload Apache service."
        return 1
    fi
    log_message "Apache reloaded successfully."
}
create_host_user_and_domain() {
    log_message "===== Step 4: Creating New Hosting User and Domain ====="

    read -rp "Enter domain (e.g., example.com): " domain
    read -rp "Enter username (e.g., alhabra): " username

    home_dir="/home/$username"
    web_root="$home_dir/ubunest"

    if id "$username" &>/dev/null; then
        log_message "[ERROR] User $username already exists."
        echo "User already exists. Aborting setup."
        return
    fi

    password=$(generate_password)

    # Create user with dedicated group (avoid group conflict)
    if getent group "$username" > /dev/null; then
        useradd -m -s /bin/bash -g "$username" "$username"
    else
        useradd -m -s /bin/bash "$username"
    fi

    echo "$username:$password" | chpasswd

    log_message "User $username created with password: $password"
    echo "[INFO] User password: $password"

    mkdir -p "$web_root"

    # Clone the repo
    if [[ -d "$web_root/.git" ]]; then
        log_message "[WARN] Repository already exists. Skipping clone."
    else
        run_cmd "Cloning Ubunest project" "git clone https://github.com/xdayeh/ubunest.git \"$web_root\""
    fi

    # Permissions
    chown -R "$username:$username" "$home_dir"
    chmod 710 "$home_dir"
    chmod -R 750 "$web_root/public"

    # Add www-data to user's group to allow Apache access
    if ! id -nG www-data | grep -qw "$username"; then
        usermod -a -G "$username" www-data
    fi

    # Apache config
    conf_path="/etc/apache2/sites-available/$username.conf"
    cat > "$conf_path" <<EOF
<VirtualHost *:80>
    ServerAdmin support@$domain
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $web_root/public

    <Directory $web_root/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/$username-error.log
    CustomLog \${APACHE_LOG_DIR}/$username-access.log combined
</VirtualHost>
EOF

    run_cmd "Enabling site" "a2ensite $username.conf"
    run_cmd "Enabling Apache modules" "a2enmod rewrite && a2enmod headers"
    run_cmd "Reloading Apache" "systemctl reload apache2"

    # Update /etc/hosts
    if ! grep -q "$domain" /etc/hosts; then
        echo "127.0.0.1 $domain www.$domain" >> /etc/hosts
        log_message "Domain $domain added to /etc/hosts"
    fi

    # Save user credentials
    echo "$username | $password | $domain" >> /root/ubunest_users.txt
    log_message "Credentials saved to /root/ubunest_users.txt"
    log_message "Hosting setup completed for $username at $domain"
}
create_mysql_user_and_db() {
    log_message "Creating MySQL Database and User"

    read -rp "Enter database name: " dbname
    read -rp "Enter MySQL username: " dbuser

    dbpass=$(generate_password)

    SQL=$(cat <<EOF
CREATE DATABASE \`$dbname\`;
CREATE USER '$dbuser'@'localhost' IDENTIFIED BY '$dbpass';
GRANT ALL PRIVILEGES ON \`$dbname\`.* TO '$dbuser'@'localhost';
ALTER USER '$dbuser'@'localhost' IDENTIFIED WITH mysql_native_password BY '$dbpass';
FLUSH PRIVILEGES;
EOF
)

    echo "$SQL" | mysql 2>/tmp/mysql_error.log

    if [[ $? -eq 0 ]]; then
        log_message "MySQL database and user created successfully."
        echo -e "\n[INFO] MySQL Credentials:"
        echo "Database Name: $dbname"
        echo "Username:     $dbuser"
        echo "Password:     $dbpass"
        echo ""
        echo "$dbuser | $dbpass | $dbname" >> /root/ubunest_mysql.txt
        log_message "Credentials saved to /root/ubunest_mysql.txt"
    else
        log_message "[ERROR] Failed to create database or user. Check /tmp/mysql_error.log"
        cat /tmp/mysql_error.log
    fi
}
# ==================== Main ====================

log_message "===== Ubunest Script Started ====="
log_message "Ubunest: Ubuntu server provisioning and maintenance in progress..."

if [[ "$1" == "mysql" ]]; then
    create_mysql_user_and_db
    exit 0
fi

log_message "Initializing system update and cleanup procedures..."

update_system
install_web_stack
secure_mysql_manual
ensure_apache_servername
reload_apache_safe
create_host_user_and_domain

run_cmd "Start Removing Unused Packages" "apt-get autoremove -y"
run_cmd "Start Cleaning Package Cache" "apt-get clean"
run_cmd "Start Cleaning /tmp Directory" "find /tmp -mindepth 1 -delete"
run_cmd "Restart Apache" "systemctl restart apache2"

log_message "===== Ubunest Script Finished ====="
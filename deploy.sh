#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Clear screen function
clear_screen() {
    clear
}

# Print colored banner
print_banner() {
    clear_screen
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}${WHITE}🤖  Telegram OSINT Bot - Deployment Manager${NC}          ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Print success message
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Print error message
print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Print warning message
print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Print info message
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_banner
    echo -e "${BOLD}${WHITE}Checking prerequisites...${NC}\n"
    
    local all_good=true
    
    # Check .env file
    if [ -f .env ]; then
        print_success ".env file found"
    else
        print_error ".env file not found!"
        print_info "Copy .env.example to .env and configure it first."
        all_good=false
    fi
    
    # Check Docker
    if command -v docker &> /dev/null; then
        print_success "Docker is installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
    else
        print_error "Docker is not installed!"
        all_good=false
    fi
    
    # Check Docker Compose V2
    if docker compose version &> /dev/null; then
        print_success "Docker Compose V2 is installed"
    else
        print_error "Docker Compose V2 is not installed!"
        all_good=false
    fi
    
    echo ""
    
    if [ "$all_good" = false ]; then
        print_error "Prerequisites check failed!"
        echo ""
        read -p "Press Enter to return to menu..."
        return 1
    else
        print_success "All prerequisites met!"
        echo ""
        return 0
    fi
}

# Docker Up
docker_up() {
    print_banner
    echo -e "${BOLD}${GREEN}Starting containers...${NC}\n"
    
    docker compose up -d --build
    
    if [ $? -eq 0 ]; then
        echo ""
        print_success "Containers started successfully!"
    else
        echo ""
        print_error "Failed to start containers!"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Docker Down
docker_down() {
    print_banner
    echo -e "${BOLD}${RED}Stopping containers...${NC}\n"
    
    docker compose down
    
    if [ $? -eq 0 ]; then
        echo ""
        print_success "Containers stopped successfully!"
    else
        echo ""
        print_error "Failed to stop containers!"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Docker Restart
docker_restart() {
    print_banner
    echo -e "${BOLD}${YELLOW}Restarting containers...${NC}\n"
    
    docker compose restart
    
    if [ $? -eq 0 ]; then
        echo ""
        print_success "Containers restarted successfully!"
    else
        echo ""
        print_error "Failed to restart containers!"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# View Logs
view_logs() {
    print_banner
    echo -e "${BOLD}${CYAN}Viewing logs (Press Ctrl+C to exit)...${NC}\n"
    
    docker compose logs -f
}

# View Status
view_status() {
    print_banner
    echo -e "${BOLD}${WHITE}Container Status:${NC}\n"
    
    docker compose ps
    
    echo ""
    read -p "Press Enter to continue..."
}

# Rebuild Containers
rebuild_containers() {
    print_banner
    echo -e "${BOLD}${MAGENTA}Rebuilding containers...${NC}\n"
    
    print_warning "This will stop and rebuild all containers."
    read -p "Continue? (y/n): " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        docker compose down
        docker compose build --no-cache
        docker compose up -d
        
        if [ $? -eq 0 ]; then
            echo ""
            print_success "Containers rebuilt successfully!"
        else
            echo ""
            print_error "Failed to rebuild containers!"
        fi
    else
        print_info "Operation cancelled."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Clean Everything
clean_everything() {
    print_banner
    echo -e "${BOLD}${RED}Clean Everything (Remove containers, volumes, and images)${NC}\n"
    
    print_warning "This will remove all containers, volumes, and images!"
    print_warning "This action cannot be undone!"
    echo ""
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" = "yes" ]; then
        docker compose down -v --rmi all
        
        if [ $? -eq 0 ]; then
            echo ""
            print_success "Cleanup completed successfully!"
        else
            echo ""
            print_error "Cleanup failed!"
        fi
    else
        print_info "Operation cancelled."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Shell Access
shell_access() {
    print_banner
    echo -e "${BOLD}${WHITE}Container Shell Access${NC}\n"
    
    # List running containers
    containers=$(docker compose ps --services --filter "status=running" 2>/dev/null)
    
    if [ -z "$containers" ]; then
        print_error "No running containers found!"
        echo ""
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${CYAN}Available containers:${NC}"
    echo "$containers" | nl -w2 -s'. '
    echo ""
    
    read -p "Select container number (or 0 to cancel): " container_num
    
    if [ "$container_num" = "0" ]; then
        print_info "Operation cancelled."
        echo ""
        read -p "Press Enter to continue..."
        return
    fi
    
    selected_container=$(echo "$containers" | sed -n "${container_num}p")
    
    if [ -n "$selected_container" ]; then
        echo ""
        print_info "Opening shell in $selected_container..."
        docker compose exec "$selected_container" /bin/bash || docker compose exec "$selected_container" /bin/sh
    else
        print_error "Invalid selection!"
        echo ""
        read -p "Press Enter to continue..."
    fi
}

# Main Menu
show_menu() {
    print_banner
    
    echo -e "${BOLD}${WHITE}Select an option:${NC}\n"
    echo -e "  ${GREEN}1${NC} - ${CYAN}Start Containers${NC}          (docker compose up)"
    echo -e "  ${RED}2${NC} - ${CYAN}Stop Containers${NC}           (docker compose down)"
    echo -e "  ${YELLOW}3${NC} - ${CYAN}Restart Containers${NC}       (docker compose restart)"
    echo -e "  ${BLUE}4${NC} - ${CYAN}View Logs${NC}                 (docker compose logs -f)"
    echo -e "  ${MAGENTA}5${NC} - ${CYAN}View Status${NC}               (docker compose ps)"
    echo -e "  ${YELLOW}6${NC} - ${CYAN}Rebuild Containers${NC}        (fresh build)"
    echo -e "  ${CYAN}7${NC} - ${CYAN}Shell Access${NC}              (exec into container)"
    echo -e "  ${RED}8${NC} - ${CYAN}Clean Everything${NC}          (remove all)"
    echo -e "  ${BLUE}9${NC} - ${CYAN}Check Prerequisites${NC}       (verify setup)"
    echo -e "  ${WHITE}0${NC} - ${CYAN}Exit${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Main program loop
main() {
    # Check prerequisites on startup
    check_prerequisites
    if [ $? -ne 0 ]; then
        exit 1
    fi
    
    while true; do
        show_menu
        read -p "Enter your choice: " choice
        
        case $choice in
            1)
                docker_up
                ;;
            2)
                docker_down
                ;;
            3)
                docker_restart
                ;;
            4)
                view_logs
                ;;
            5)
                view_status
                ;;
            6)
                rebuild_containers
                ;;
            7)
                shell_access
                ;;
            8)
                clean_everything
                ;;
            9)
                check_prerequisites
                read -p "Press Enter to continue..."
                ;;
            0)
                print_banner
                print_success "Goodbye! 👋"
                echo ""
                exit 0
                ;;
            *)
                print_banner
                print_error "Invalid option! Please try again."
                sleep 2
                ;;
        esac
    done
}

# Run main program
main
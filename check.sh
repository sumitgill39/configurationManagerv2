#!/bin/bash

# AI Configuration Manager - Project Files Checker for Mac
# This script verifies all required files are in place

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
TOTAL_FILES=0
FOUND_FILES=0
MISSING_FILES=0

# Function to print colored output
print_color() {
    printf "${1}${2}${NC}\n"
}

# Function to print header
print_header() {
    echo ""
    print_color $BLUE "=================================="
    print_color $BLUE "$1"
    print_color $BLUE "=================================="
}

# Function to check if file exists and has content
check_file() {
    local file_path="$1"
    local description="$2"
    local required_size="${3:-1}"  # Default minimum size is 1 byte
    
    TOTAL_FILES=$((TOTAL_FILES + 1))
    
    if [[ -f "$file_path" ]]; then
        local file_size=$(stat -f%z "$file_path" 2>/dev/null || echo "0")
        if [[ $file_size -ge $required_size ]]; then
            printf "  ✅ %-50s %s\n" "$description" "($(format_size $file_size))"
            FOUND_FILES=$((FOUND_FILES + 1))
            return 0
        else
            printf "  ⚠️  %-50s %s\n" "$description" "(exists but empty)"
            MISSING_FILES=$((MISSING_FILES + 1))
            return 1
        fi
    else
        printf "  ❌ %-50s %s\n" "$description" "(missing)"
        MISSING_FILES=$((MISSING_FILES + 1))
        return 1
    fi
}

# Function to format file size
format_size() {
    local size=$1
    if [[ $size -lt 1024 ]]; then
        echo "${size}B"
    elif [[ $size -lt 1048576 ]]; then
        echo "$((size / 1024))KB"
    else
        echo "$((size / 1048576))MB"
    fi
}

# Function to check directory structure
check_directory() {
    local dir_path="$1"
    local description="$2"
    
    if [[ -d "$dir_path" ]]; then
        print_color $GREEN "  ✅ $description"
        return 0
    else
        print_color $RED "  ❌ $description (missing)"
        return 1
    fi
}

# Function to check if required tools are installed
check_prerequisites() {
    print_header "CHECKING PREREQUISITES"
    
    local tools=("docker" "docker-compose" "curl" "git")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version=""
            case $tool in
                "docker")
                    version=$(docker --version 2>/dev/null | cut -d' ' -f3 | cut -d',' -f1)
                    ;;
                "docker-compose")
                    version=$(docker-compose --version 2>/dev/null | cut -d' ' -f3 | cut -d',' -f1)
                    ;;
                "curl")
                    version=$(curl --version 2>/dev/null | head -n1 | cut -d' ' -f2)
                    ;;
                "git")
                    version=$(git --version 2>/dev/null | cut -d' ' -f3)
                    ;;
            esac
            printf "  ✅ %-20s %s\n" "$tool" "($version)"
        else
            printf "  ❌ %-20s %s\n" "$tool" "(not installed)"
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo ""
        print_color $YELLOW "Missing tools installation commands:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                "docker")
                    echo "  - Install Docker Desktop from: https://docs.docker.com/desktop/mac/"
                    ;;
                "docker-compose")
                    echo "  - Docker Compose comes with Docker Desktop"
                    ;;
                "curl")
                    echo "  - curl is usually pre-installed on macOS"
                    ;;
                "git")
                    echo "  - Install via: xcode-select --install"
                    ;;
            esac
        done
    fi
}

# Function to validate file content
validate_file_content() {
    local file_path="$1"
    local expected_content="$2"
    local description="$3"
    
    if [[ -f "$file_path" ]]; then
        if grep -q "$expected_content" "$file_path" 2>/dev/null; then
            printf "  ✅ %-50s %s\n" "$description" "(content valid)"
            return 0
        else
            printf "  ⚠️  %-50s %s\n" "$description" "(content invalid)"
            return 1
        fi
    else
        printf "  ❌ %-50s %s\n" "$description" "(file missing)"
        return 1
    fi
}

# Function to check Python requirements
check_python_requirements() {
    if [[ -f "backend/requirements.txt" ]]; then
        local flask_count=$(grep -c "Flask" backend/requirements.txt || echo "0")
        local total_deps=$(grep -c "==" backend/requirements.txt || echo "0")
        
        if [[ $flask_count -gt 0 && $total_deps -gt 10 ]]; then
            printf "  ✅ %-50s %s\n" "Python dependencies" "($total_deps packages)"
        else
            printf "  ⚠️  %-50s %s\n" "Python dependencies" "(incomplete: $total_deps packages)"
        fi
    fi
}

# Function to check Node.js dependencies
check_node_dependencies() {
    if [[ -f "frontend/package.json" ]]; then
        if grep -q "react" frontend/package.json && grep -q "react-dom" frontend/package.json; then
            local react_version=$(grep "react" frontend/package.json | head -n1 | cut -d'"' -f4)
            printf "  ✅ %-50s %s\n" "Node.js dependencies" "(React $react_version)"
        else
            printf "  ⚠️  %-50s %s\n" "Node.js dependencies" "(React missing)"
        fi
    fi
}

# Main execution
main() {
    clear
    print_color $PURPLE "🤖 AI Configuration Manager - Project Files Checker"
    print_color $PURPLE "===================================================="
    echo ""
    print_color $CYAN "Checking project structure and files..."
    echo ""
    
    # Check if we're in the right directory
    if [[ ! -f "docker-compose.yml" ]]; then
        print_color $RED "❌ Error: docker-compose.yml not found in current directory"
        print_color $YELLOW "Please run this script from the ai-configuration-manager root directory"
        exit 1
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Check directory structure
    print_header "CHECKING DIRECTORY STRUCTURE"
    check_directory "backend" "Backend directory"
    check_directory "frontend" "Frontend directory"
    check_directory "frontend/src" "Frontend source directory"
    check_directory "frontend/public" "Frontend public directory"
    check_directory "nginx" "Nginx directory"
    
    # Check core configuration files
    print_header "CHECKING CORE CONFIGURATION FILES"
    check_file "docker-compose.yml" "Docker Compose configuration" 500
    check_file ".env.example" "Environment template" 200
    check_file "Makefile" "Development commands" 1000
    check_file "README.md" "Project documentation" 2000
    
    # Check backend files
    print_header "CHECKING BACKEND FILES"
    check_file "backend/app.py" "Flask application" 5000
    check_file "backend/requirements.txt" "Python dependencies" 200
    check_file "backend/Dockerfile" "Backend Docker configuration" 300
    check_file "backend/seed_data.py" "Sample data script" 1000
    
    # Check frontend files
    print_header "CHECKING FRONTEND FILES"
    check_file "frontend/src/App.js" "React application" 5000
    check_file "frontend/package.json" "Node.js dependencies" 500
    check_file "frontend/Dockerfile" "Frontend Docker configuration" 200
    check_file "frontend/public/index.html" "HTML template" 500
    check_file "frontend/nginx.conf" "Frontend nginx config" 300
    
    # Check nginx configuration
    print_header "CHECKING NGINX CONFIGURATION"
    check_file "nginx/nginx.conf" "Main nginx configuration" 1000
    
    # Check file content validation
    print_header "VALIDATING FILE CONTENT"
    validate_file_content "backend/app.py" "Flask" "Flask app structure"
    validate_file_content "frontend/src/App.js" "import React" "React component structure"
    validate_file_content "docker-compose.yml" "services:" "Docker Compose structure"
    validate_file_content "nginx/nginx.conf" "upstream backend" "Nginx proxy configuration"
    
    # Check dependencies
    print_header "CHECKING DEPENDENCIES CONFIGURATION"
    check_python_requirements
    check_node_dependencies
    
    # Summary
    print_header "SUMMARY"
    printf "Total files checked: %d\n" $TOTAL_FILES
    printf "Files found: %s%d%s\n" $GREEN $FOUND_FILES $NC
    printf "Files missing/invalid: %s%d%s\n" $RED $MISSING_FILES $NC
    
    echo ""
    
    if [[ $MISSING_FILES -eq 0 ]]; then
        print_color $GREEN "🎉 All files are in place! Your project is ready to go!"
        echo ""
        print_color $CYAN "Next steps:"
        echo "  1. Copy .env.example to .env: cp .env.example .env"
        echo "  2. Start the application: docker-compose up -d"
        echo "  3. Access frontend: http://localhost:3000"
        echo "  4. Access backend: http://localhost:5000"
        echo ""
        print_color $YELLOW "Default login: admin / admin123"
    else
        print_color $RED "❌ Some files are missing or invalid!"
        echo ""
        print_color $YELLOW "Please ensure all files are created with the proper content."
        print_color $YELLOW "Refer to the project documentation for file contents."
        exit 1
    fi
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
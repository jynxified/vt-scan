#!/bin/bash
####################################################################################################
# Scan files for malware using the VirusTotal web API
# Written by @Jynx
# https://github.com/jynxified
# jynxified@proton.me
# 
# History:
# 1.0.0 (2026-07-26) - Initial version
#
# Disclaimer:
# This script is provided "as is" without any warranty of any kind, either expressed or implied.
# Use it entirely at your own risk. The author (that's me) shall not be liable for any damages,
# data loss, system failures, or serious trouble you, your relatives, their neighbours or beloved
# pets might get into caused by the use or misuse of this script.
#
# Licensed under "CC BY-NC-ND 4.0" (https://creativecommons.org/licenses/by-nc-nd/4.0/).
####################################################################################################

# Text colors
BOLD="\e[1m"
BOLD_BLUE="\e[1;34m"
BLUE="\e[34m"
RED="\e[31m"
GREEN="\e[32m"
CYAN="\e[36m"
WHITE="\e[37m"
BOLD_MAGENTA="\e[1;35m"
MAGENTA="\e[35m"
YELLOW="\e[33m"
GREY="\e[90m"
BLINK="\e[5m"
NC="\e[0m"

# Variables
P_API_KEY_FILE=""
P_SCAN_THROTTLE_DELAY=0
P_VERBOSE_MODE="N"
P_ULTRA_VERBOSE_MODE="N"
P_GRACE_ATTEMPTS=5
P_GRACE_DELAY=10
P_MAXDEPTH=10
P_LOGFILE=""
P_PATHS=()
P_FILES=()

VT_URL="https://www.virustotal.com/api/v3/files"

PROCESSED_PATHS_CNTR=0
SCANNED_FILES_CNTR=0
MALICIOUS_FILES_CNTR=0
SUSPICIOUS_FILES_CNTR=0
UNDETECTED_FILES_CNTR=0
HARMLESS_FILES_CNTR=0
SKIPPED_CNTR=0
FAILED_CNTR=0

MALICIOUS_FILES=()
SUSPICIOUS_FILES=()

####################################################################################################
# Validate and extract input parameters
####################################################################################################

#
# Displays usage information for the script with all parameters and options.
#
function showHelp {

    echo
    echo -e "${BOLD}Scan files for malware using the VirusTotal web API${NC}"
    echo
    echo -e "...::: Version 1.0.0 | ${YELLOW}@${BLUE}Jynx${NC} | jynxified@proton.me | ${BLUE}https://github.com/jynxified${NC} :::..."
    echo
    echo -e "Usage: vt-scan ${MAGENTA}OPTIONS${NC} ${YELLOW}PATH|PATTERN${NC} [${YELLOW}PATH|PATTERN${NC} ...]"
    echo
    echo -e "  ${MAGENTA}-a, --apikey FILE${NC}\t\t${BOLD}MANDATORY${NC}. File containing a VirusTotal API access key. If you do"
    echo -e "\t\t\t\tnot have one yet, you need to sign up at VirusTotal first. You"
    echo -e "\t\t\t\tcan find more information on this issue here:"
    echo -e "\t\t\t\t${BLUE}https://docs.virustotal.com/docs/please-give-me-an-api-key${NC}"
    echo    
    echo -e "  ${MAGENTA}-t, --throttle SECONDS${NC}\t${BOLD}OPTIONAL${NC}. Delay in seconds between two consecutive file scans."
    echo -e "\t\t\t\tDepending on your account type, VirusTotal only allows a certain"
    echo -e "\t\t\t\tnumber of requests (4 per minute and 500 per day for free accounts)."
    echo -e "\t\t\t\tThis option can be used to throttle scan requests accordingly. The"
    echo -e "\t\t\t\tdefault value is $P_SCAN_THROTTLE_DELAY."
    echo    
    echo -e "  ${MAGENTA}-g, --grace ATTEMPTS${NC}\t\t${BOLD}OPTIONAL${NC}. The number of attempts to retrieve a file's VirusTotal"
    echo -e "\t\t\t\tscan report while it is still in progress. Scanning new files (i.e.,"
    echo -e "\t\t\t\tfiles that VirusTotal has not seen before) takes some time to complete."
    echo -e "\t\t\t\tIn this case, the program will pause and repeatedly try to retrieve"
    echo -e "\t\t\t\tthe report. The default value is $P_GRACE_ATTEMPTS, with a $P_GRACE_DELAY-second delay between"
    echo -e "\t\t\t\tconsecutive attempts. If the report still cannot be retrieved after"
    echo -e "\t\t\t\tthis \"grace period,\" the file will be skipped."
    echo    
    echo -e "  ${MAGENTA}-m, --maxdepth DEPTH${NC}\t\t${BOLD}OPTIONAL${NC}. Maximum recursion depth for subdirectory file searches."
    echo -e "\t\t\t\tThe default value is $P_MAXDEPTH. The value 0 means no recursion."
    echo    
    echo -e "  ${MAGENTA}-v, --verbose${NC}\t\t\t${BOLD}OPTIONAL${NC}. Debug mode. Display detailed status information for each"
    echo -e "\t\t\t\texecuted processing step. Without this option, only the result of"
    echo -e "\t\t\t\ta file scan is printed as a CSV-formatted line."
    echo    
    echo -e "  ${MAGENTA}-vv, --ultraverbose${NC}\t\t${BOLD}OPTIONAL${NC}. Trace mode. Display extremely detailed status information"
    echo -e "\t\t\t\tfor each executed processing step. Displays even more information"
    echo -e "\t\t\t\tthan -v | --verbose."
    echo    
    echo -e "  ${MAGENTA}-l, --log FILE${NC}\t\t${BOLD}OPTIONAL${NC}. Writes all debug and trace messages to the specified log"
    echo -e "\t\t\t\tfile instead of printing them to the console. This option only takes"
    echo -e "\t\t\t\teffect if the -v or -vv option is also used."
    echo
    echo -e "Licensed under ${BOLD}CC BY-NC-ND 4.0${NC} (https://creativecommons.org/licenses/by-nc-nd/4.0/)"
}

#
# Validates an input parameter.
# 
# Input parameters:
#  - [1] : The name of the input parameter.
#  - [2] : The value of the input parameter.
#
function validateParam {

    PARAM_NAME=$1
    PARAM_VALUE=$2
    if [[ -z "$PARAM_VALUE" || "$PARAM_VALUE" == -* ]]
    then
        echo -e "${RED}Option \"$PARAM_NAME\" requires an argument.${NC}"
        exit 1
    fi
}


# Parse input parameters. 
while [[ $# -gt 0 ]]
do
    case $1 in
        -a|--apikey)
            validateParam $1 $2
            P_API_KEY_FILE="$2"
            shift 2
            ;;
        -t|--throttle)
            validateParam $1 $2
            P_SCAN_THROTTLE_DELAY=$2
            shift 2
            ;;
        -g|--grace)
            validateParam $1 $2
            P_GRACE_ATTEMPTS=$2
            shift 2
            ;;
        -m|--maxdepth)
            validateParam $1 $2
            P_MAXDEPTH=$2
            shift 2
            ;;
        -v|--verbose)
            P_VERBOSE_MODE="Y"
            shift
            ;;
        -vv|--ultraverbose)
            P_VERBOSE_MODE="Y"
            P_ULTRA_VERBOSE_MODE="Y"
            shift
            ;;
        -l|--logfile)
            validateParam $1 $2
            P_LOGFILE=$2
            shift 2
            ;;
        -h|--help)
            showHelp
            exit 0
            ;;
        -*)
            echo -e "${RED}Unknown option '$1'. Use -h|--help for a list of all supported options.${NC}"
            exit 1
            ;;
        *)
            P_PATHS+=("$1")
            shift
            ;;
    esac
done

####################################################################################################
# Functions
####################################################################################################

#
# Writes a log message.
# 
# Input parameters:
#  - [1] : Verbose level (0=info, 1=debug, 2=trace)
#  - [2] : The log message
#
function logMessage {

    VERBOSE_LEVEL=$1
    LOG_LINE=$2
    if [[ ("$VERBOSE_LEVEL" == "0") || ("$VERBOSE_LEVEL" == "1" && "$P_VERBOSE_MODE" == "Y") || ("$VERBOSE_LEVEL" == "2" && "$P_ULTRA_VERBOSE_MODE" == "Y") ]]
    then
        if [[ ("$VERBOSE_LEVEL" == "0") || ("$P_LOGFILE" == "") ]]
        then
            echo -e "$LOG_LINE"
        else
            echo -e "$LOG_LINE" >>$P_LOGFILE
        fi
    fi
}

#
# Check if a VirusTotal scan report already exists for a file.
#
# Input parameters:
#  - [1] : The VirusTotal API key to use.
#  - [2] : The path and name of the file to be scanned.
#
# Return values:
#  - 0 : Scan report for the file is available.
#  - 1 : Request failed.
#  - 2 : No scan report available, the file is unknown to VirusTotal.
#
function checkForExistingReport {

    API_KEY=$1
    FILE=$2
    
    CHECKSUM=$(sha256sum "$FILE" | sed 's/ .*$//g')
    URL="$VT_URL/$CHECKSUM"

    logMessage 2 "${BLUE}[ SCAN ]${NC} Calling URL: $URL"

    RESPONSE=$(curl -s --request GET \
        --url $URL/$CHECKSUM \
        --header "x-apikey: $API_KEY")
    
    ERROR_CODE=$?
    if [ $ERROR_CODE != 0 ]
    then
        logMessage 1 "${BLUE}[ SCAN ]${NC} ${RED}GET request failed, error code $ERROR_CODE:${NC} $URL"
        if [ "$VERBOSE_LEVEL" != 2 ]
        then
            logMessage 1 "${BLUE}[ SCAN ]${NC} ${MAGENTA}$RESPONSE${NC}"
        fi
        ((FAILED_CNTR++))
        return 1
    fi
        
    logMessage 2 "${BLUE}[ SCAN ]${NC} Response: ${MAGENTA}$RESPONSE${NC}"
    
    if [[ $(echo "$RESPONSE" | fgrep -c "NotFoundError") == 0 ]]
    then
        return 2
    fi
    
    echo "$RESPONSE"
    
    return 0
}

#
# Upload file to VirusTotal for malware analysis.
#
# Input parameters:
#  - [1] : The VirusTotal API key to use.
#  - [2] : The path and name of the file to be uploaded.
#
# Return values:
#  - 0 : Upload was successful.
#  - 1 : Upload failed.
#  - 2 : Upload was rejected by VirusTotal.
#
function uploadFile {

    API_KEY=$1
    FILE=$2

    logMessage 1 "${BLUE}[ SCAN ]${NC} Uploading file: ${BLUE}$VT_URL${NC}"

    VT_UPLOAD_RESPONSE=$(curl -s --request POST \
        --url $VT_URL \
        --header "accept: application/json" \
        --header "content-type: multipart/form-data" \
        --header "x-apikey: $API_KEY" \
        --form "file=@$FILE")
    RC_CODE=$?

    if [ $RC_CODE != 0 ]
    then
        logMessage 1 "${BLUE}[ SCAN ]${NC} ${RED}Upload failed, error code: $RC_CODE.${NC}"
        if [ "$VERBOSE_LEVEL" != 2 ]
        then
            logMessage 1 "${BLUE}[ SCAN ]${NC} ${MAGENTA}$VT_UPLOAD_RESPONSE${NC}"
        fi
        ((FAILED_CNTR++))
        return 1 # Upload failed
    fi
        
    logMessage 2 "${BLUE}[ SCAN ]${NC} Response: ${MAGENTA}$VT_UPLOAD_RESPONSE${NC}"

    if [[ $(echo "$VT_UPLOAD_RESPONSE" | fgrep -c "\"error\"") != 0 ]]
    then
        UPLOAD_ERROR=$(echo "$VT_UPLOAD_RESPONSE" | sed -e 's/^.*code\": \"//g' -e 's/\".*$//g')
        logMessage 1 "${BLUE}[ SCAN ]${NC} ${RED}Upload was rejected by VirusTotal, error code: \"$UPLOAD_ERROR\".${NC}"
        ((FAILED_CNTR++))
        return 2 # Upload rejected
    fi

    return 0 # Upload successful
}

#
# Calculates the percentage of two numbers.
# 
# Input parameters:
#  - [1] : The part number.
#  - [2] : The total number.
#
function calcPercentage {
    PART=$1
    TOTAL=$2
    echo $(( PART * 100 / TOTAL ))
}

#
# Map a percentage value to a textual malware infection probability (LOW, MEDIUM, HIGH).
#
# Input parameters:
#  - [1] : Percentage value.
#
function getMalwareCertaintyLevel {
    PERCENTAGE=$1
    if [[ "$PERCENTAGE" -le 20 ]]
    then
        echo "LOW"
    elif [[ "$PERCENTAGE" -le 50 ]]
    then
        echo "MEDIUM"
    else
        echo "HIGH"
    fi
}

#
# Scan a single file for malware using VirusTotal.
#
# Input parameters:
#  - [1] : VirusTotal API key.
#  - [2] : Path and name of the file to be scanned.
#
# Return values:
#  - 0 : Scan was successful.
#  - 1 : Scan report is queued, i.e., in progress.
#  - 2 : Scan failed.
#
function scanFile {

    API_KEY=$1
    FILE=$2

    # Search for existing VT scan report.
    CHECKSUM=$(sha256sum "$FILE" | sed 's/ .*$//g')
    
    logMessage 2 "${BLUE}[ SCAN ]${NC} Verifying whether a VirusTotal scan report exists: ${BLUE}$VT_URL/$CHECKSUM${NC}"
    
    VT_SCAN_RESPONSE=$(curl -s --request GET \
        --url $VT_URL/$CHECKSUM \
        --header "x-apikey: $API_KEY")
    RC_CODE=$?
    
    if [ $RC_CODE != 0 ]
    then
        logMessage 1 "${BLUE}[ SCAN ]${NC} ${RED}Request failed, error code $RC_CODE.${NC}"
        if [ "$VERBOSE_LEVEL" != 2 ]
        then
            logMessage 1 "${BLUE}[ SCAN ]${NC} ${MAGENTA}$VT_UPLOAD_RESPONSE${NC}"
        fi
        ((FAILED_CNTR++))
        return 2 # Scan failed
    fi
    
    logMessage 2 "${BLUE}[ SCAN ]${NC} Response: ${MAGENTA}$VT_SCAN_RESPONSE${NC}"
    
    if [[ $(echo "$VT_SCAN_RESPONSE" | fgrep -c "\"NotFoundError\"") != 0 ]] # File was not uploaded to VT yet.
    then
        
        logMessage 2 "${BLUE}[ SCAN ]${NC} File was not uploaded to VirusTotal yet."

        uploadFile $API_KEY "$FILE"
        RC_CODE=$?

        if [[ $RC_CODE == 0 ]]
        then
            return 1 # Scan report queued
        else
            return 2 # Scan failed
        fi

    elif [[ $(echo "$VT_SCAN_RESPONSE" | fgrep -c "\"status\": \"queued\"") != 0 ]] # Scan report is currently in progress
    then
    
       logMessage 2 "${BLUE}[ SCAN ]${NC} Scan report is currently in progress."
       return 1 # Scan report queued
        
    elif [[ ( $(echo "$VT_SCAN_RESPONSE" | fgrep -c "\"last_analysis_stats\"") != 0) || ($(echo "$VT_SCAN_RESPONSE" | fgrep -c "\"status\": \"completed\"") != 0) ]] # Scan report is available
    then

        logMessage 2 "${BLUE}[ SCAN ]${NC} Scan report is available."
    
        # Extract the relevant numbers from the report.    
        MALICIOUS_HITS=$(echo "$VT_SCAN_RESPONSE" | sed -e 's/^.*malicious\": \([0-9]*\),/\1/g' -e 's/ .*$//g')
        SUSPICIOUS_HITS=$(echo "$VT_SCAN_RESPONSE" | sed -e 's/^.*suspicious\": \([0-9]*\),/\1/g' -e 's/ .*$//g')
        UNDETECTED_HITS=$(echo "$VT_SCAN_RESPONSE" | sed -e 's/^.*undetected\": \([0-9]*\),/\1/g' -e 's/ .*$//g')
        HARMLESS_HITS=$(echo "$VT_SCAN_RESPONSE" | sed -e 's/^.*harmless\": \([0-9]*\),/\1/g' -e 's/ .*$//g')
        FULL_HITS=$((MALICIOUS_HITS + SUSPICIOUS_HITS + UNDETECTED_HITS + HARMLESS_HITS))
        
        logMessage 1 "${BLUE}[ SCAN ]${NC} Scan result: ${RED}$MALICIOUS_HITS${NC} malicious marks, ${YELLOW}$SUSPICIOUS_HITS${NC} suspicious marks, ${BLUE}$UNDETECTED_HITS${NC} undetected marks, ${GREEN}$HARMLESS_HITS${NC} harmless marks"
        
        OVERALL_RESULT="unspecified"
        if [[ "$MALICIOUS_HITS" > 0 ]]
        then
            OVERALL_RESULT="malicious"
            ((MALICIOUS_FILES_CNTR++))
            MALICIOUS_HITS_PERCENTAGE=$(calcPercentage $MALICIOUS_HITS $FULL_HITS)
            MALICIOUS_CERTAINTY=$(getMalwareCertaintyLevel $MALICIOUS_HITS_PERCENTAGE)
            MALICIOUS_FILES+=("$(echo "$FILE (certainty: $MALICIOUS_HITS_PERCENTAGE% -> $MALICIOUS_HITS/$FULL_HITS [$MALICIOUS_CERTAINTY])")")
        elif [[ "$SUSPICIOUS_HITS" > 0 ]]
        then
            OVERALL_RESULT="suspicious"
            ((SUSPICIOUS_FILES_CNTR++))
            SUSPICIOUS_HITS_PERCENTAGE=$(calcPercentage $SUSPICIOUS_HITS $FULL_HITS)
            SUSPICIOUS_CERTAINTY=$(getMalwareCertaintyLevel $SUSPICIOUS_HITS_PERCENTAGE)
            SUSPICIOUS_FILES+=("$(echo "$FILE (certainty: $SUSPICIOUS_HITS_PERCENTAGE% -> $SUSPICIOUS_HITS/$FULL_HITS [$SUSPICIOUS_CERTAINTY])")")
        elif [[ "$UNDETECTED_HITS" > 0 ]]
        then
            OVERALL_RESULT="undetected"
            ((UNDETECTED_FILES_CNTR++))
        elif [[ "$HARMLESS_HITS" > 0 ]]
        then
            OVERALL_RESULT="harmless"
            ((HARMLESS_FILES_CNTR++))
        fi
        
        logMessage 0 "\"$OVERALL_RESULT\"|$MALICIOUS_HITS|$SUSPICIOUS_HITS|$UNDETECTED_HITS|$HARMLESS_HITS|\"$FILE\""
        
        return 0 # Scan successful
    
    elif [[ $(echo "$VT_SCAN_RESPONSE" | egrep -c "(QuotaExceededError|429 Too Many Requests)") != 0 ]]
    then
    
        echo -e "${RED}You exceeded the maximum number of allowed requests for your VirusTotal account. Use -t|--throttle or wait for the rate limit to reset.${NC}"
        exit 1
    
    else

        logMessage 1 "${BLUE}[ SCAN ]${NC} ${YELLOW}Unknown scan status, skipping file. For more information on the cause, rescan it using the -vv|--ultraverbose option.${NC}"
        ((SKIPPED_CNTR++))
        return 2 # Scan failed
    fi
}

####################################################################################################
# Main code
####################################################################################################

#
# Load and validate VirusTotal web API key
#
if [ "$P_API_KEY_FILE" == "" ]
then
    echo -e "${RED}No API key file was specified, please use option -a | --apikey.${NC}"
    exit 1
fi

if [ ! -e "$P_API_KEY_FILE" ]
then
    echo -e "${RED}API key file does not exist:${NC} $P_API_KEY_FILE"
    exit 1
fi

logMessage 2 "${BLUE}[ INIT ]${NC} Reading API key from file: ${BLUE}$P_API_KEY_FILE${NC}"

VT_API_KEY=$(cat "$P_API_KEY_FILE" | egrep "[a-z0-9]+" | head -n 1)
if [ "$VT_API_KEY" == "" ]
then
    echo -e "${RED}No valid API key found in file:${NC} $P_API_KEY_FILE"
    exit 1
fi

logMessage 2 "${BLUE}[ INIT ]${NC} VirusTotal API key: ${YELLOW}$VT_API_KEY${NC}"

#
# Resolve and locate all files for scanning based on the specified paths.
#
for TARGET_PATH in "${P_PATHS[@]}"
do
    while IFS= read -r FILE
    do
        P_FILES+=("$FILE")
    done < <(find "$TARGET_PATH" -maxdepth $P_MAXDEPTH -type f 2>/dev/null)
done

if [[ "${#P_FILES[@]}" == 0 ]]
then
    logMessage 1 "${RED}No files found for scanning.${NC}"
    exit 0
fi

#
# Scan files for malware.
#
START_TIME=$(date +%s)

logMessage 2 "${BLUE}[ INIT ]${NC} VirusTotal URL: ${BLUE}$VT_URL${NC}"

NUM_FILES=${#P_FILES[@]}
for FILE in "${P_FILES[@]}"
do

    ((PROCESSED_PATHS_CNTR++))
    
    GRACE_ATTEMPT_CNTR=0
    
    logMessage 1 "${BLUE}[ SCAN ]${NC} ${BOLD}Scanning #$PROCESSED_PATHS_CNTR${NC}: ${BLUE}$FILE${NC}"

    # Skip all paths that do not exist.
    if [[ (! -e "$FILE") || (-d "$FILE") ]]
    then
        logMessage 1 "${BLUE}[ SCAN ]${NC} ${YELLOW}Skipping, path does not exist or is not a file.${NC}"
        continue
    fi

    # Scan file.
    ((SCANNED_FILES_CNTR++))

    while :
    do
    
        scanFile $VT_API_KEY "$FILE"
        RC_CODE=$?
        
        if [[ "$RC_CODE" == 1 ]]
        then
        
            ((GRACE_ATTEMPT_CNTR++))
            if [[ "$GRACE_ATTEMPT_CNTR" < "$P_GRACE_ATTEMPTS" ]]
            then
                logMessage 1 "${BLUE}[ WAIT ]${NC} Gracefully waiting $P_GRACE_DELAY seconds for VirusTotal report (attempt $GRACE_ATTEMPT_CNTR of $P_GRACE_ATTEMPTS)..."
                sleep $P_GRACE_DELAY
            else
                if [[ "$P_GRACE_ATTEMPTS" > 0 ]]
                then
                    logMessage 1 "${BLUE}[ SCAN ]${NC} ${YELLOW}All grace attempts failed, VirusTotal report is still not available, therefore skipping file.${NC}"
                fi
                ((SKIPPED_CNTR++))
                break
            fi        
        else
            break
        fi
        
    done
    
    # Take a break before the next scan if throttling was configured.
    if [[ ($P_SCAN_THROTTLE_DELAY > 0) && ("$SCANNED_FILES_CNTR" != "$NUM_FILES") ]]
    then
        logMessage 1 "${BLUE}[ WAIT ]${NC} Throttling scan speed, waiting $P_SCAN_THROTTLE_DELAY second(s)..."
        sleep $P_SCAN_THROTTLE_DELAY
    fi

done

END_TIME=$(date +%s)
TIME_DIFF=$((END_TIME - START_TIME))

#
# Print results.
#
logMessage 1 "${BLUE}[STATUS]${NC} ${BOLD}$PROCESSED_PATHS_CNTR path(s) processed, $SCANNED_FILES_CNTR file(s) scanned, duration $(date -u -d "@$TIME_DIFF" +%H:%M:%S)${NC}: ${RED}$MALICIOUS_FILES_CNTR${NC} malicious, ${YELLOW}$SUSPICIOUS_FILES_CNTR${NC} suspicious, ${BLUE}$UNDETECTED_FILES_CNTR${NC} undetected, ${GREEN}$HARMLESS_FILES_CNTR${NC} harmless, ${GREY}$SKIPPED_CNTR${NC} skipped, ${MAGENTA}$FAILED_CNTR${NC} failed"

if [[ "$MALICIOUS_FILES_CNTR" > 0 ]]
then
    logMessage 1 "${BLUE}[RESULT]${NC} ${RED}${MALICIOUS_FILES_CNTR} malicious file(s) detected:${NC}"
    for MALICIOUS_FILE in "${MALICIOUS_FILES[@]}"
    do
        logMessage 1 "${BLUE}[RESULT]${NC}      ${RED}$MALICIOUS_FILE${NC}"
    done
fi
if [[ "$SUSPICIOUS_FILES_CNTR" > 0 ]]
then
    logMessage 1 "${BLUE}[RESULT]${NC} ${YELLOW}${SUSPICIOUS_FILES_CNTR} suspicious file(s) detected:${NC}"
    for SUSPICIOUS_FILE in "${SUSPICIOUS_FILES[@]}"
    do
        logMessage 1 "${BLUE}[RESULT]${NC}      ${YELLOW}$SUSPICIOUS_FILE${NC}"
    done
fi
if [[ "$MALICIOUS_FILES_CNTR" == 0 && "$SUSPICIOUS_FILES_CNTR" == 0 ]]
then
    logMessage 1 "${BLUE}[RESULT]${NC} ${GREEN}No malicious or suspicious files detected.${NC}"
fi

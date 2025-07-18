#!/bin/bash
# Network Partition Chaos Script
# Simulates network partitions between Security Envelopes nodes

set -e

# Configuration
NODES=("se-node1" "se-node2" "se-node3" "se-node4" "se-node5")
PARTITION_PROBABILITY=0.1
PARTITION_DURATION=30
RECOVERY_TIME=60
LOG_FILE="/chaos-scripts/network-partition.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log "ERROR: Docker is not available"
        exit 1
    fi
}

# Get container IP address
get_container_ip() {
    local container_name=$1
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name" 2>/dev/null || echo ""
}

# Create network partition between two nodes
create_partition() {
    local node1=$1
    local node2=$2
    
    local ip1=$(get_container_ip "$node1")
    local ip2=$(get_container_ip "$node2")
    
    if [[ -z "$ip1" || -z "$ip2" ]]; then
        log "WARNING: Could not get IP addresses for $node1 or $node2"
        return 1
    fi
    
    log "Creating partition between $node1 ($ip1) and $node2 ($ip2)"
    
    # Block traffic between the two nodes using iptables
    docker exec "$node1" iptables -A INPUT -s "$ip2" -j DROP 2>/dev/null || true
    docker exec "$node1" iptables -A OUTPUT -d "$ip2" -j DROP 2>/dev/null || true
    docker exec "$node2" iptables -A INPUT -s "$ip1" -j DROP 2>/dev/null || true
    docker exec "$node2" iptables -A OUTPUT -d "$ip1" -j DROP 2>/dev/null || true
    
    log "Partition created successfully"
}

# Remove network partition between two nodes
remove_partition() {
    local node1=$1
    local node2=$2
    
    local ip1=$(get_container_ip "$node1")
    local ip2=$(get_container_ip "$node2")
    
    if [[ -z "$ip1" || -z "$ip2" ]]; then
        log "WARNING: Could not get IP addresses for $node1 or $node2"
        return 1
    fi
    
    log "Removing partition between $node1 ($ip1) and $node2 ($ip2)"
    
    # Remove iptables rules
    docker exec "$node1" iptables -D INPUT -s "$ip2" -j DROP 2>/dev/null || true
    docker exec "$node1" iptables -D OUTPUT -d "$ip2" -j DROP 2>/dev/null || true
    docker exec "$node2" iptables -D INPUT -s "$ip1" -j DROP 2>/dev/null || true
    docker exec "$node2" iptables -D OUTPUT -d "$ip1" -j DROP 2>/dev/null || true
    
    log "Partition removed successfully"
}

# Check if containers are running
check_containers() {
    log "Checking container status..."
    
    for node in "${NODES[@]}"; do
        if docker ps --format "{{.Names}}" | grep -q "^${node}$"; then
            log "✓ $node is running"
        else
            log "✗ $node is not running"
            return 1
        fi
    done
    
    log "All containers are running"
}

# Test connectivity between nodes
test_connectivity() {
    local node1=$1
    local node2=$2
    
    local ip2=$(get_container_ip "$node2")
    if [[ -z "$ip2" ]]; then
        return 1
    fi
    
    # Test connectivity using ping
    if docker exec "$node1" ping -c 1 -W 2 "$ip2" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Run connectivity tests
run_connectivity_tests() {
    log "Running connectivity tests..."
    
    local failed_tests=0
    
    for i in "${!NODES[@]}"; do
        for j in "${!NODES[@]}"; do
            if [[ $i -ne $j ]]; then
                if test_connectivity "${NODES[$i]}" "${NODES[$j]}"; then
                    log "✓ ${NODES[$i]} -> ${NODES[$j]}: CONNECTED"
                else
                    log "✗ ${NODES[$i]} -> ${NODES[$j]}: DISCONNECTED"
                    ((failed_tests++))
                fi
            fi
        done
    done
    
    log "Connectivity test completed. Failed tests: $failed_tests"
    return $failed_tests
}

# Simulate random network partitions
simulate_partitions() {
    log "Starting network partition simulation..."
    
    local iteration=1
    
    while true; do
        log "=== Iteration $iteration ==="
        
        # Randomly select nodes for partition
        for i in "${!NODES[@]}"; do
            for j in "${!NODES[@]}"; do
                if [[ $i -lt $j ]]; then
                    # Random chance of creating partition
                    if (( RANDOM % 100 < PARTITION_PROBABILITY * 100 )); then
                        log "Random partition triggered between ${NODES[$i]} and ${NODES[$j]}"
                        
                        # Create partition
                        if create_partition "${NODES[$i]}" "${NODES[$j]}"; then
                            log "Partition active for $PARTITION_DURATION seconds"
                            sleep "$PARTITION_DURATION"
                            
                            # Remove partition
                            remove_partition "${NODES[$i]}" "${NODES[$j]}"
                            log "Partition removed, recovery period: $RECOVERY_TIME seconds"
                            sleep "$RECOVERY_TIME"
                        fi
                    fi
                fi
            done
        done
        
        # Run connectivity tests
        run_connectivity_tests
        
        # Check for isolation violations
        check_isolation_violations
        
        log "=== End of iteration $iteration ==="
        ((iteration++))
        
        # Small delay between iterations
        sleep 10
    done
}

# Check for tenant isolation violations
check_isolation_violations() {
    log "Checking for tenant isolation violations..."
    
    # Test cross-tenant access attempts
    for node in "${NODES[@]}"; do
        # Try to access another tenant's namespace
        local response=$(docker exec "$node" curl -s -w "%{http_code}" \
            -H "X-Tenant-ID: tenant-test-001" \
            -H "X-Target-Tenant-ID: tenant-test-002" \
            "http://localhost:8080/api/v1/namespaces/ns-002/resources" \
            -o /dev/null 2>/dev/null || echo "000")
        
        if [[ "$response" == "403" ]]; then
            log "✓ $node: Cross-tenant access properly denied"
        elif [[ "$response" == "200" ]]; then
            log "✗ $node: CRITICAL - Cross-tenant access allowed!"
            echo "ISOLATION_VIOLATION" > /chaos-scripts/isolation_violation.flag
        else
            log "? $node: Unexpected response code: $response"
        fi
    done
}

# Cleanup function
cleanup() {
    log "Cleaning up network partitions..."
    
    # Remove all iptables rules
    for node in "${NODES[@]}"; do
        docker exec "$node" iptables -F 2>/dev/null || true
    done
    
    log "Cleanup completed"
}

# Signal handlers
trap cleanup EXIT
trap 'log "Received SIGINT, stopping..."; exit 0' INT
trap 'log "Received SIGTERM, stopping..."; exit 0' TERM

# Main execution
main() {
    log "=== Network Partition Chaos Script Started ==="
    
    # Check prerequisites
    check_docker
    
    # Check container status
    if ! check_containers; then
        log "ERROR: Not all containers are running"
        exit 1
    fi
    
    # Initial connectivity test
    log "Running initial connectivity test..."
    run_connectivity_tests
    
    # Start partition simulation
    simulate_partitions
}

# Run main function
main "$@" 
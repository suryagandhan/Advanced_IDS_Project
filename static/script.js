let monitorInterval = null;
let attackChart = null;

document.addEventListener('DOMContentLoaded', () => {
    
    // Animation for confidence bar in results
    const fill = document.querySelector('.confidence-fill');
    if (fill) {
        const width = fill.style.width;
        fill.style.width = '0%';
        setTimeout(() => {
            fill.style.width = width;
        }, 300);
    }
    
    // Form submission UI logic
    const form = document.getElementById('detectionForm');
    if (form) {
        form.addEventListener('submit', function() {
            const btnText = document.querySelector('.btn-text');
            const loader = document.getElementById('btnLoader');
            
            if(btnText) btnText.style.display = 'none';
            if(loader) loader.style.display = 'inline-block';
            
            const btn = document.getElementById('analyzeBtn');
            if(btn) btn.disabled = true;
            document.body.style.cursor = 'wait';
        });
    }

    // Initialize Chart
    const ctx = document.getElementById('attackTypeChart');
    if (ctx) {
        attackChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['No Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#334155'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // Auto-fetch stats once on load to populate the dashboard metrics immediately
    if (document.getElementById('stat-total')) {
        fetchStats();
    }
});

function toggleMonitoring() {
    const btn = document.getElementById('startMonitorBtn');
    if (monitorInterval) {
        clearInterval(monitorInterval);
        monitorInterval = null;
        btn.innerHTML = '▶ Start Monitoring';
        btn.classList.remove('danger-btn');
        
        // Disconnect hardware OS sniffer
        fetch('/toggle_live_sniffer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'stop'})
        });
    } else {
        btn.innerHTML = '⏸ Stop Monitoring';
        btn.classList.add('danger-btn');
        monitorInterval = setInterval(fetchStats, 2000);
        fetchStats(); // initial fetch
        
        // Hook hardware OS sniffer stream
        fetch('/toggle_live_sniffer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'start'})
        });
    }
}

function fetchStats() {
    fetch('/get_stats')
        .then(res => res.json())
        .then(data => {
            // Update Stats
            const statTotal = document.getElementById('stat-total');
            const statAttacks = document.getElementById('stat-attacks');
            if(statTotal) statTotal.innerText = data.stats.total_analyzed;
            if(statAttacks) statAttacks.innerText = data.stats.total_attacks;
            
            // Update Chart
            if (data.stats.total_attacks > 0 && attackChart) {
                const labels = Object.keys(data.stats.attack_types);
                const values = Object.values(data.stats.attack_types);
                
                // Color mapping
                const colors = labels.map(l => l.includes('Normal') || l.includes('BENIGN') ? '#34d399' : '#f87171');
                
                attackChart.data.labels = labels;
                attackChart.data.datasets[0].data = values;
                attackChart.data.datasets[0].backgroundColor = colors;
                attackChart.update();
            }
            
            // Update Logs
            const consoleEl = document.getElementById('logConsole');
            if (consoleEl && data.logs.length > 0) {
                consoleEl.innerHTML = '';
                
                // Track total logs to prevent overflow
                let currentLogs = data.logs;
                
                // Add heartbeat if system is idle (logs haven't changed and it's mostly INFO traffic)
                if (currentLogs.length < 5 || (currentLogs[currentLogs.length-1] && currentLogs[currentLogs.length-1].includes('Monitoring'))) {
                    // System is idle
                    const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
                    currentLogs.push(`[${timeStr}] [INFO] System Heartbeat: Waiting for inbound packets on eth0...`);
                }

                currentLogs.forEach(log => {
                    let logClass = 'log-line';
                    
                    // Base Colors
                    if (log.includes('[WARN') || log.includes('detected')) logClass += ' log-warn';
                    else if (log.includes('[ERROR]')) logClass += ' log-error';
                    else logClass += ' log-info';
                    
                    // Parse out string natively
                    // Example: [14:02:30] [INFO] ACTION: Blocking IP 192.168.1.1
                    let formattedLog = log;
                    
                    // Highlight Timestamps [HH:MM:SS]
                    formattedLog = formattedLog.replace(/\[(\d{2}:\d{2}:\d{2})\]/g, '<span class="term-time">[$1]</span>');
                    
                    // Highlight Levels [INFO], [WARN], etc.
                    formattedLog = formattedLog.replace(/\[(INFO|WARN|ERROR)\]/g, '<span class="term-level">[$1]</span>');
                    
                    // Highlight IPs
                    formattedLog = formattedLog.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="term-ip">$1</span>');
                    
                    // Highlight specific critical action words
                    formattedLog = formattedLog.replace(/(ACTION:|Blocking|detected|Botnet|DDoS|PortScan|SYN Flood|UDP Flood|ICMP Flood|Ping of Death|XMAS Scan|NULL Scan)/g, '<span class="term-action">$1</span>');
                    
                    const div = document.createElement('div');
                    div.className = logClass;
                    div.innerHTML = formattedLog;
                    consoleEl.appendChild(div);
                });
                
                // Add blinking cursor
                const cursor = document.createElement('div');
                cursor.innerHTML = '<span class="cursor-blink"></span>';
                consoleEl.appendChild(cursor);
                
                consoleEl.scrollTop = consoleEl.scrollHeight;
            }
        })
        .catch(err => console.error("Error fetching stats:", err));
}



function fillForm(type) {
    switch(type) {
        case 'normal':
            document.getElementById('source_ip').value = `192.168.1.${Math.floor(Math.random() * 200) + 1}`;
            document.getElementById('protocol').value = "6";
            document.getElementById('src_port').value = "27915";
            document.getElementById('dst_port').value = "22";
            document.getElementById('flow_duration').value = "4304672";
            document.getElementById('flow_bytes').value = "81984";
            document.getElementById('total_fwd_packets').value = "51";
            document.getElementById('total_bwd_packets').value = "49";
            document.getElementById('packet_length_mean').value = "816";
            break;
            
        case 'botnet':
            document.getElementById('source_ip').value = `10.0.0.${Math.floor(Math.random() * 200) + 1}`;
            document.getElementById('protocol').value = "6";
            document.getElementById('src_port').value = "12345";
            document.getElementById('dst_port').value = "8080";
            document.getElementById('flow_duration').value = "8500000";
            document.getElementById('flow_bytes').value = "500";
            document.getElementById('total_fwd_packets').value = "15";
            document.getElementById('total_bwd_packets').value = "10";
            document.getElementById('packet_length_mean').value = "120.0";
            break;
            
        case 'ddos':
            document.getElementById('source_ip').value = `172.16.0.${Math.floor(Math.random() * 200) + 1}`;
            document.getElementById('protocol').value = "17";
            document.getElementById('src_port').value = "4444";
            document.getElementById('dst_port').value = "80";
            document.getElementById('flow_duration').value = "1200000";
            document.getElementById('flow_bytes').value = "150000";
            document.getElementById('total_fwd_packets').value = "850";
            document.getElementById('total_bwd_packets').value = "10";
            document.getElementById('packet_length_mean').value = "45.0";
            break;
            
        case 'portscan':
            document.getElementById('source_ip').value = `192.168.10.${Math.floor(Math.random() * 200) + 1}`;
            document.getElementById('protocol').value = "6";
            document.getElementById('src_port').value = "55555";
            document.getElementById('dst_port').value = "22";
            document.getElementById('flow_duration').value = "50";
            document.getElementById('flow_bytes').value = "0";
            document.getElementById('total_fwd_packets').value = "1";
            document.getElementById('total_bwd_packets').value = "0";
            document.getElementById('packet_length_mean').value = "0";
            break;
    }
}

// View Controller for Tabbed Interface
function switchTab(evt, tabId) {
    // Hide all tab contents
    const contents = document.getElementsByClassName("tab-content");
    for (let i = 0; i < contents.length; i++) {
        contents[i].style.display = "none";
    }
    
    // Remove active class from all buttons
    const tabs = document.getElementsByClassName("tab-btn");
    for (let i = 0; i < tabs.length; i++) {
        tabs[i].classList.remove("active");
    }
    
    // Show current tab, and add active class to button
    document.getElementById(tabId).style.display = "block";
    if(evt && evt.currentTarget) {
        evt.currentTarget.classList.add("active");
    } else {
        // Fallback for auto-switching
        const btn = document.querySelector(`.tab-btn[onclick*="${tabId}"]`);
        if(btn) btn.classList.add("active");
    }
}

// Reset button loading states when navigating backward via browser BFCache
window.addEventListener('pageshow', function(event) {
    // Reset Manual Simulation Button
    const btnText = document.querySelector('.btn-text');
    const loader = document.getElementById('btnLoader');
    const btn = document.getElementById('analyzeBtn');
    
    if (btnText) btnText.style.display = 'inline-block';
    if (loader) loader.style.display = 'none';
    if (btn) btn.disabled = false;
    
    // Reset Batch Upload Button
    const batchBtn = document.getElementById('batchBtn');
    if (batchBtn) {
        batchBtn.innerText = 'Upload & Analyze Data';
        batchBtn.style.opacity = '1';
    }
    
    // Reset cursor
    document.body.style.cursor = 'default';
});

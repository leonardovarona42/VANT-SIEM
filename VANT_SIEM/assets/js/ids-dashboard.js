/**
 * JavaScript para dashboards de IDS/IPS
 * Funcionalidades comunes para Suricata y Snort
 */

// Variables globales
let autoRefreshInterval;
let isAutoRefreshActive = false;
let charts = {};

// Función para actualizar datos dinámicamente
async function refreshData() {
    try {
        const currentUrl = new URL(window.location);
        const params = new URLSearchParams(currentUrl.search);
        
        // Usar la API endpoint
        // Normalizar endpoints de API desde rutas de dashboard
        // /siem/ids/suricata/ -> /siem/ids/suricata/api/
        // /siem/ids/snort/ -> /siem/ids/snort/api/
        let apiUrl = currentUrl.pathname;
        if (apiUrl.endsWith('/suricata/')) {
            apiUrl = apiUrl.replace('/suricata/', '/suricata/api/');
        } else if (apiUrl.endsWith('/snort/')) {
            apiUrl = apiUrl.replace('/snort/', '/snort/api/');
        } else if (apiUrl.includes('/suricata/')) {
            apiUrl = apiUrl.replace('/suricata', '/suricata/api');
        } else if (apiUrl.includes('/snort/')) {
            apiUrl = apiUrl.replace('/snort', '/snort/api');
        }
        const response = await fetch(`${apiUrl}?${params.toString()}`);
        const data = await response.json();
        
        if (data.success) {
            // Actualizar estadísticas
            updateStatsFromAPI(data.stats);
            
            // Actualizar tabla
            updateTableFromAPI(data.logs, data.total_count);
            
            // Mostrar notificación de actualización
            showUpdateNotification();
        } else {
            throw new Error(data.error || 'Error desconocido');
        }
        
    } catch (error) {
        console.error('Error actualizando datos:', error);
        showErrorNotification('Error al actualizar datos');
    }
}

// Actualizar estadísticas desde API
function updateStatsFromAPI(stats) {
    const statElements = document.querySelectorAll('.ids-stat-number');
    const statKeys = ['total', 'critical', 'high', 'medium', 'low', 'last_24h', 'errors', 'warnings', 'avg_packets_per_sec', 'avg_bytes_per_sec', 'total_bytes', 'total_packets'];
    
    statKeys.forEach((key, index) => {
        if (statElements[index] && stats[key] !== undefined) {
            const newValue = stats[key];
            const currentValue = statElements[index].textContent;
            
            if (newValue.toString() !== currentValue) {
                // Animación de cambio
                statElements[index].style.transform = 'scale(1.1)';
                statElements[index].style.color = '#4facfe';
                statElements[index].textContent = newValue;
                
                setTimeout(() => {
                    statElements[index].style.transform = 'scale(1)';
                    statElements[index].style.color = '';
                }, 300);
            }
        }
    });
}

// Actualizar tabla desde API
function updateTableFromAPI(logs, totalCount) {
    const currentTableBody = document.querySelector('#logs-table-body');
    const currentCount = document.querySelector('#total-count');
    
    if (currentTableBody) {
        // Generar nuevo HTML para la tabla
        const newTableHTML = generateTableHTML(logs);
        
        // Comparar contenido
        if (newTableHTML !== currentTableBody.innerHTML) {
            // Agregar efecto de fade
            currentTableBody.style.opacity = '0.5';
            
            setTimeout(() => {
                currentTableBody.innerHTML = newTableHTML;
                currentTableBody.style.opacity = '1';
                
                // Re-aplicar event listeners a los nuevos botones
                attachEventListeners();
            }, 200);
        }
    }
    
    // Actualizar contador total
    if (currentCount) {
        currentCount.textContent = `${totalCount} total`;
    }
}

// Generar HTML de la tabla desde los datos de la API
function generateTableHTML(logs) {
    const logType = new URLSearchParams(window.location.search).get('log_type') || 'alerts';
    
    if (logType === 'alerts') {
        return logs.map(log => `
            <tr class="${log.severity == 1 ? 'table-danger' : log.severity == 2 ? 'table-warning' : ''}">
                <td>
                    <span class="text-info">${log.timestamp}</span>
                </td>
                <td>
                    <span class="ids-badge-modern ${log.severity == 1 ? 'ids-badge-critical' : log.severity == 2 ? 'ids-badge-high' : log.severity == 3 ? 'ids-badge-medium' : 'ids-badge-low'}">
                        ${log.severity == 1 ? 'Critical' : log.severity == 2 ? 'High' : log.severity == 3 ? 'Medium' : 'Low'}
                    </span>
                </td>
                <td>
                    <span class="text-warning">${log.src_ip}</span>
                </td>
                <td>
                    <span class="text-info">${log.dest_ip}</span>
                </td>
                <td>
                    <span class="badge bg-secondary">${log.protocol}</span>
                </td>
                <td>
                    <span class="text-light">${log.signature_id}</span>
                </td>
                <td>
                    <span class="text-light">${log.message.length > 80 ? log.message.substring(0, 80) + '...' : log.message}</span>
                </td>
                <td>
                    <span class="text-muted">${log.classification || '-'}</span>
                </td>
                <td>
                    <div class="btn-group" role="group">
                        <button class="ids-btn-modern" onclick="showDetails(${log.id})" title="Ver detalles completos">
                            <i class="fas fa-eye"></i>Detalles
                        </button>
                        <button class="ids-btn-modern" onclick="analyzeIP('${log.src_ip}')" title="Analizar IP origen">
                            <i class="fas fa-search"></i>Analizar
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }
    
    // Agregar más tipos de logs según sea necesario
    return logs.map(log => `
        <tr>
            <td>${log.timestamp}</td>
            <td>${JSON.stringify(log)}</td>
        </tr>
    `).join('');
}

// Mostrar notificación de actualización
function showUpdateNotification() {
    const indicator = document.getElementById('auto-refresh-indicator');
    if (indicator) {
        indicator.style.background = 'var(--ids-success)';
        indicator.querySelector('span').textContent = 'Datos actualizados';
        
        setTimeout(() => {
            if (isAutoRefreshActive) {
                indicator.querySelector('span').textContent = 'Auto-actualización activa';
            }
        }, 2000);
    }
}

// Mostrar notificación de error
function showErrorNotification(message) {
    const indicator = document.getElementById('auto-refresh-indicator');
    if (indicator) {
        indicator.style.background = 'var(--ids-danger)';
        indicator.querySelector('span').textContent = message;
        
        setTimeout(() => {
            if (isAutoRefreshActive) {
                indicator.style.background = 'var(--ids-success)';
                indicator.querySelector('span').textContent = 'Auto-actualización activa';
            }
        }, 3000);
    }
}

// Función para mostrar detalles
function showDetails(logId) {
    const detailsContent = document.getElementById('detailsContent');
    if (detailsContent) {
        detailsContent.textContent = 'Cargando detalles...';
        const modal = new bootstrap.Modal(document.getElementById('detailsModal'));
        modal.show();
        
        // Aquí se implementaría la carga real de detalles via AJAX
        setTimeout(() => {
            detailsContent.textContent = `Detalles del log ID: ${logId}\n\nEsta funcionalidad se puede expandir para mostrar información detallada del evento.`;
        }, 500);
    }
}

// Función para mostrar detalles de log
function showLogDetails(rawLine) {
    const detailsContent = document.getElementById('detailsContent');
    if (detailsContent) {
        detailsContent.textContent = rawLine;
        const modal = new bootstrap.Modal(document.getElementById('detailsModal'));
        modal.show();
    }
}

// Función para analizar IP
function analyzeIP(ip) {
    window.open(`/siem/dashboard/analysis/ip/?ip=${ip}`, '_blank');
}

// Iniciar auto-actualización
function startAutoRefresh() {
    if (isAutoRefreshActive) return;
    
    isAutoRefreshActive = true;
    autoRefreshInterval = setInterval(refreshData, 10000); // Cada 10 segundos
    
    // Actualizar UI
    const startBtn = document.getElementById('start-auto-btn');
    const stopBtn = document.getElementById('stop-auto-btn');
    const indicator = document.getElementById('auto-refresh-indicator');
    
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn) stopBtn.style.display = 'inline-flex';
    if (indicator) indicator.classList.remove('inactive');
    
    showUpdateNotification();
}

// Detener auto-actualización
function stopAutoRefresh() {
    if (!isAutoRefreshActive) return;
    
    isAutoRefreshActive = false;
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
    
    // Actualizar UI
    const startBtn = document.getElementById('start-auto-btn');
    const stopBtn = document.getElementById('stop-auto-btn');
    const indicator = document.getElementById('auto-refresh-indicator');
    
    if (startBtn) startBtn.style.display = 'inline-flex';
    if (stopBtn) stopBtn.style.display = 'none';
    if (indicator) {
        indicator.classList.add('inactive');
        indicator.querySelector('span').textContent = 'Auto-actualización detenida';
    }
}

// Adjuntar event listeners a los botones
function attachEventListeners() {
    // Los event listeners se adjuntan automáticamente via onclick en el HTML
    // Esta función se puede usar para adjuntar listeners más complejos si es necesario
}

// Render de gráficos
function renderCharts() {
    const chartData = window.chartData || {};

    // Destruir gráficos existentes si existen
    Object.values(charts).forEach(chart => {
        if (chart) chart.destroy();
    });
    charts = {};

    // Timeline
    const tl = chartData.timeline || [];
    const tlLabels = tl.map(t => Object.values(t)[0]);
    const tlValues = tl.map(t => t.count);
    
    const timelineCanvas = document.getElementById('chartTimeline');
    if (timelineCanvas) {
        charts.timeline = new Chart(timelineCanvas, {
            type: 'line',
            data: { 
                labels: tlLabels, 
                datasets: [{ 
                    label: 'Eventos', 
                    data: tlValues, 
                    borderColor: '#667eea', 
                    backgroundColor: 'rgba(102, 126, 234, 0.2)',
                    tension: 0.4,
                    borderWidth: 3,
                    pointBackgroundColor: '#667eea',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4
                }] 
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false,
                aspectRatio: 2,
                plugins: { 
                    legend: { 
                        display: false 
                    } 
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#b8c5d6' },
                        grid: { color: '#16213e' }
                    },
                    x: {
                        ticks: { color: '#b8c5d6' },
                        grid: { color: '#16213e' }
                    }
                }
            }
        });
    }

    // Protocolos
    const pd = chartData.proto_dist || [];
    const protocolsCanvas = document.getElementById('chartProtocols');
    if (protocolsCanvas) {
        charts.protocols = new Chart(protocolsCanvas, {
            type: 'doughnut',
            data: { 
                labels: pd.map(x=>x.proto||x.protocol), 
                datasets: [{ 
                    data: pd.map(x=>x.count), 
                    backgroundColor: [
                        'rgba(102, 126, 234, 0.8)',
                        'rgba(118, 75, 162, 0.8)',
                        'rgba(79, 172, 254, 0.8)',
                        'rgba(0, 242, 254, 0.8)',
                        'rgba(67, 233, 123, 0.8)',
                        'rgba(56, 249, 215, 0.8)',
                        'rgba(250, 112, 154, 0.8)'
                    ],
                    borderWidth: 3,
                    borderColor: '#1a1a2e'
                }] 
            },
            options: { 
                responsive: true,
                maintainAspectRatio: false,
                aspectRatio: 1,
                plugins: {
                    legend: {
                        labels: {
                            color: '#b8c5d6',
                            font: {
                                size: 12
                            }
                        }
                    }
                }
            }
        });
    }

    // Puertos
    const sp = chartData.top_src_ports || [];
    const dp = chartData.top_dest_ports || [];
    const portsCanvas = document.getElementById('chartPorts');
    if (portsCanvas) {
        charts.ports = new Chart(portsCanvas, {
            type: 'bar',
            data: {
                labels: [...new Set([...sp.map(x=>x.src_port), ...dp.map(x=>x.dest_port)])].slice(0,10),
                datasets: [
                    { 
                        label: 'Origen', 
                        data: sp.map(x=>x.count), 
                        backgroundColor: 'rgba(102, 126, 234, 0.8)',
                        borderColor: '#667eea',
                        borderWidth: 1
                    },
                    { 
                        label: 'Destino', 
                        data: dp.map(x=>x.count), 
                        backgroundColor: 'rgba(79, 172, 254, 0.8)',
                        borderColor: '#4facfe',
                        borderWidth: 1
                    }
                ]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false,
                aspectRatio: 2,
                plugins: { 
                    legend: { 
                        position: 'bottom',
                        labels: {
                            color: '#b8c5d6'
                        }
                    } 
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#b8c5d6' },
                        grid: { color: '#16213e' }
                    },
                    x: {
                        ticks: { color: '#b8c5d6' },
                        grid: { color: '#16213e' }
                    }
                }
            }
        });
    }

    // IPs
    const si = chartData.top_src_ips || [];
    const di = chartData.top_dest_ips || [];
    const ipsCanvas = document.getElementById('chartIPs');
    if (ipsCanvas) {
        charts.ips = new Chart(ipsCanvas, {
            type: 'bar',
            data: {
                labels: [...new Set([...si.map(x=>x.src_ip), ...di.map(x=>x.dest_ip)])].slice(0,10),
                datasets: [
                    { 
                        label: 'Origen', 
                        data: si.map(x=>x.count), 
                        backgroundColor: 'rgba(67, 233, 123, 0.8)',
                        borderColor: '#43e97b',
                        borderWidth: 1
                    },
                    { 
                        label: 'Destino', 
                        data: di.map(x=>x.count), 
                        backgroundColor: 'rgba(56, 249, 215, 0.8)',
                        borderColor: '#38f9d7',
                        borderWidth: 1
                    }
                ]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false,
                aspectRatio: 2,
                plugins: { 
                    legend: { 
                        position: 'bottom',
                        labels: {
                            color: '#b8c5d6'
                        }
                    } 
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#b8c5d6' },
                        grid: { color: '#16213e' }
                    },
                    x: {
                        ticks: { color: '#b8c5d6' },
                        grid: { color: '#16213e' }
                    }
                }
            }
        });
    }
}

// ============================================
// KIBANA-LIKE CHART RENDERING
// ============================================

/**
 * Render charts in Kibana style
 */
function renderKibanaCharts() {
    const chartData = window.chartData || {};
    
    // Destroy existing charts
    Object.values(charts).forEach(chart => {
        if (chart) chart.destroy();
    });
    charts = {};
    
    // Kibana color palette
    const kibanaColors = [
        '#6092c0', '#54b399', '#d6bf57', '#da8b45', '#e74856',
        '#9170b8', '#ca8b45', '#3c8dbc', '#00a65a', '#f39c12'
    ];
    
    // Timeline Chart (Activity over Time)
    const timelineCanvas = document.getElementById('chartTimeline');
    if (timelineCanvas && chartData.timeline && chartData.timeline.length > 0) {
        const tl = chartData.timeline;
        charts.timeline = new Chart(timelineCanvas, {
            type: 'line',
            data: {
                labels: tl.map(t => Object.values(t)[0]),
                datasets: [{
                    label: 'Events',
                    data: tl.map(t => t.count),
                    borderColor: '#6092c0',
                    backgroundColor: 'rgba(96, 146, 192, 0.2)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointBackgroundColor: '#6092c0',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 1,
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: '#e3e8f2' },
                        ticks: { color: '#6a717d' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#6a717d' }
                    }
                }
            }
        });
    }
    
    // Event Types Pie Chart
    const eventTypesCanvas = document.getElementById('chartEventTypes');
    if (eventTypesCanvas && chartData.proto_dist && chartData.proto_dist.length > 0) {
        const pd = chartData.proto_dist;
        charts.eventTypes = new Chart(eventTypesCanvas, {
            type: 'pie',
            data: {
                labels: pd.map(x => x.proto || x.protocol || 'Unknown'),
                datasets: [{
                    data: pd.map(x => x.count),
                    backgroundColor: kibanaColors,
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#1a1a1a',
                            font: { size: 12 },
                            padding: 12
                        }
                    }
                }
            }
        });
    }
    
    // Transport Protocols Donut Chart
    const transportCanvas = document.getElementById('chartTransport');
    if (transportCanvas && chartData.proto_dist && chartData.proto_dist.length > 0) {
        const pd = chartData.proto_dist;
        charts.transport = new Chart(transportCanvas, {
            type: 'doughnut',
            data: {
                labels: pd.map(x => x.proto || x.protocol || 'Unknown'),
                datasets: [{
                    data: pd.map(x => x.count),
                    backgroundColor: kibanaColors,
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#1a1a1a',
                            font: { size: 12 },
                            padding: 12
                        }
                    }
                }
            }
        });
    }
    
    // Network Protocols Chart
    const networkCanvas = document.getElementById('chartNetwork');
    if (networkCanvas && chartData.app_proto_dist && chartData.app_proto_dist.length > 0) {
        const ap = chartData.app_proto_dist;
        charts.network = new Chart(networkCanvas, {
            type: 'doughnut',
            data: {
                labels: ap.map(x => x.app_proto || 'Unknown'),
                datasets: [{
                    data: ap.map(x => x.count),
                    backgroundColor: kibanaColors,
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#1a1a1a',
                            font: { size: 12 },
                            padding: 12
                        }
                    }
                }
            }
        });
    }
    
    // Top Ports Chart (Horizontal Bar)
    const portsCanvas = document.getElementById('chartPorts');
    if (portsCanvas && (chartData.top_src_ports || chartData.top_dest_ports)) {
        const sp = chartData.top_src_ports || [];
        const dp = chartData.top_dest_ports || [];
        const allPorts = [...new Set([...sp.map(x=>x.src_port), ...dp.map(x=>x.dest_port)])].slice(0, 10);
        
        charts.ports = new Chart(portsCanvas, {
            type: 'bar',
            data: {
                labels: allPorts.map(String),
                datasets: [
                    {
                        label: 'Source',
                        data: allPorts.map(port => {
                            const found = sp.find(x => x.src_port === port);
                            return found ? found.count : 0;
                        }),
                        backgroundColor: 'rgba(96, 146, 192, 0.8)',
                        borderColor: '#6092c0',
                        borderWidth: 1
                    },
                    {
                        label: 'Destination',
                        data: allPorts.map(port => {
                            const found = dp.find(x => x.dest_port === port);
                            return found ? found.count : 0;
                        }),
                        backgroundColor: 'rgba(84, 179, 153, 0.8)',
                        borderColor: '#54b399',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#1a1a1a' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: '#e3e8f2' },
                        ticks: { color: '#6a717d' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#6a717d' }
                    }
                }
            }
        });
    }
    
    // Top IPs Chart
    const ipsCanvas = document.getElementById('chartIPs');
    if (ipsCanvas && (chartData.top_src_ips || chartData.top_dest_ips)) {
        const si = chartData.top_src_ips || [];
        const di = chartData.top_dest_ips || [];
        const allIPs = [...new Set([...si.map(x=>x.src_ip), ...di.map(x=>x.dest_ip)])].slice(0, 10);
        
        charts.ips = new Chart(ipsCanvas, {
            type: 'bar',
            data: {
                labels: allIPs,
                datasets: [
                    {
                        label: 'Source',
                        data: allIPs.map(ip => {
                            const found = si.find(x => x.src_ip === ip);
                            return found ? found.count : 0;
                        }),
                        backgroundColor: 'rgba(214, 191, 87, 0.8)',
                        borderColor: '#d6bf57',
                        borderWidth: 1
                    },
                    {
                        label: 'Destination',
                        data: allIPs.map(ip => {
                            const found = di.find(x => x.dest_ip === ip);
                            return found ? found.count : 0;
                        }),
                        backgroundColor: 'rgba(218, 139, 69, 0.8)',
                        borderColor: '#da8b45',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#1a1a1a' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: '#e3e8f2' },
                        ticks: { color: '#6a717d' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: {
                            color: '#6a717d',
                            maxRotation: 45,
                            minRotation: 45
                        }
                    }
                }
            }
        });
    }
}

/**
 * Update metric value with animation
 */
function updateMetricValue(elementId, newValue) {
    const element = document.getElementById(elementId);
    if (element) {
        const currentValue = parseInt(element.textContent) || 0;
        if (newValue !== currentValue) {
            element.style.transform = 'scale(1.1)';
            element.style.transition = 'transform 0.3s ease';
            element.textContent = newValue;
            setTimeout(() => {
                element.style.transform = 'scale(1)';
            }, 300);
        }
    }
}

/**
 * Update all dashboard metrics
 */
function updateDashboardMetrics(stats) {
    updateMetricValue('total-events', stats.total || 0);
    updateMetricValue('critical-events', stats.critical || 0);
    updateMetricValue('high-events', stats.high || 0);
    updateMetricValue('medium-events', stats.medium || 0);
    updateMetricValue('low-events', stats.low || 0);
    updateMetricValue('last-24h-events', stats.last_24h || 0);
}

/**
 * Initialize Kibana-like dashboard
 */
function initKibanaDashboard() {
    // Render charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        renderKibanaCharts();
    }
    
    // Add panel interaction handlers
    document.querySelectorAll('.kbnGridPanel').forEach(panel => {
        panel.addEventListener('mouseenter', function() {
            this.style.zIndex = '10';
        });
        panel.addEventListener('mouseleave', function() {
            this.style.zIndex = '';
        });
    });
    
    // Initialize tooltips
    document.querySelectorAll('[data-tooltip]').forEach(element => {
        element.addEventListener('mouseenter', function() {
            const tooltip = document.createElement('div');
            tooltip.className = 'euiToolTip';
            tooltip.textContent = this.dataset.tooltip;
            document.body.appendChild(tooltip);
        });
    });
}

// Inicialización
document.addEventListener('DOMContentLoaded', function() {
    // Iniciar auto-actualización por defecto
    startAutoRefresh();
    
    // Pausar auto-actualización cuando el usuario interactúa
    let userActivityTimeout;
    
    function resetUserActivity() {
        clearTimeout(userActivityTimeout);
        if (isAutoRefreshActive) {
            stopAutoRefresh();
        }
        userActivityTimeout = setTimeout(() => {
            if (!isAutoRefreshActive) {
                startAutoRefresh();
            }
        }, 30000); // Reanudar después de 30 segundos de inactividad
    }
    
    // Detectar actividad del usuario
    document.addEventListener('click', resetUserActivity);
    document.addEventListener('keypress', resetUserActivity);
    document.addEventListener('scroll', resetUserActivity);
    
    // Limpiar interval al salir de la página
    window.addEventListener('beforeunload', function() {
        stopAutoRefresh();
    });
    
    // Renderizar gráficos si están disponibles
    if (typeof Chart !== 'undefined') {
        renderCharts();
    }
});

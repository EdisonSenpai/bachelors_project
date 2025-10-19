function renderAlerts(alerts) {
  const table = document.getElementById('alertTable');
  table.innerHTML = '';
  alerts.forEach(alert => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${alert.timestamp || '-'}</td>
      <td>${alert.src_ip || '-'}</td>
      <td>${alert.dest_ip || '-'}</td>
      <td>${alert.proto || '-'}</td>
      <td>${alert.signature || '-'}</td>
    `;
    table.appendChild(row);
  });
  document.getElementById("alertsCount").innerText = `Total alerte: ${alerts.length}`;
}

function renderDevices(devices) {
  const table = document.getElementById('devicesTable');
  table.innerHTML = '';
  devices.forEach(device => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${device.ip || '-'}</td>
      <td>${device.mac || '-'}</td>
      <td>${device.name || '-'}</td>
      <td>${device.status || '-'}</td>
    `;
    table.appendChild(row);
  });

}

function renderTrendChart(data) {
    const countsByDay = {};

    data.forEach(alert => {
        const date = new Date(alert.timestamp);
        const day = date.toISOString().split('T')[0]; // YYYY-MM-DD
        countsByDay[day] = (countsByDay[day] || 0) + 1;
    });

    // Sortam ultimele 7 zile
    const sortedDays = Object.keys(countsByDay).sort().slice(-7);
    const trendData = sortedDays.map(day => countsByDay[day]);

    if (!trendChart) {
        const ctx = document.getElementById('trendChart').getContext('2d');
        trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: sortedDays,
                datasets: [{
                    label: 'Trend 7 Zile',
                    data: trendData,
                    borderColor: 'magenta',
                    backgroundColor: 'rgba(255, 0, 255, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                animation: false,
                plugins: {
                    legend: {
                        labels: {
                            color: 'magenta'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: 'white' }
                    },
                    y: {
                        ticks: { color: 'white' }
                    }
                }
            }
        });
    } else {
        trendChart.data.labels = sortedDays;
        trendChart.data.datasets[0].data = trendData;
        trendChart.update();
    }
}

function renderSHAPExplanation(data) {
  let html = `<h3>Predictie AI: ${["Normal", "Malicious"][data.prediction]}</h3><table><tr><th>Atribut</th><th>Valoare</th><th>Impact SHAP</th></tr>`;
  data.explanation.forEach(e => {
    html += `<tr>
      <td>${e.feature}</td>
      <td>${e.value}</td>
      <td style="color:${e.impact > 0 ? 'red' : 'lightgreen'}">${e.impact.toFixed(4)}</td>
    </tr>`;
  });
  html += `</table>`;
  document.getElementById("shapOutput").innerHTML = html;
}

function renderUserAlerts(alerts, username) {
  const container = document.getElementById('userAlertsContainer');
  container.innerHTML = `<h3>📋 Alerte pentru <span style="color:cyan">${username}</span></h3>`;

  const reversedAlerts = alerts.slice().reverse(); // cele mai noi primele
  
  let html = `
    <table>
      <thead><tr>
        <th>TIMESTAMP</th><th>IP SURSA</th><th>IP DESTINATIE</th><th>PROTOCOL</th><th>SEMNATURA</th><th>ETICHETA AI</th>
      </tr></thead><tbody>`;

  reversedAlerts.forEach(alert => {
    html += `<tr>
      <td>${alert.timestamp}</td>
      <td>${alert.src_ip}</td>
      <td>${alert.dest_ip}</td>
      <td>${alert.proto}</td>
      <td>${alert.signature}</td>
      <td>${alert.label || 'N/A'}</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  container.innerHTML += html;
}

document.getElementById("adminUsersTab").addEventListener("click", () => {
  fetchUserDevices();
});
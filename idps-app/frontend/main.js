let allAlerts = [];
let wasOffline = false;
let previousDevices = [];
let knownMacs = new Set(); // Set pentru a urmari MAC-urile cunoscute

const statusSpan = document.getElementById('status');

async function loadAlerts() {
  try {
    const res = await fetch('http://10.222.8.24:5003/alerts');
    const data = await res.json();
    allAlerts = data;
    filterAlerts();
    populateDayDropdown(data);
    filterByDay(); // actualizeaza graficul dupa ce am populat dropdown-ul
    //updateChart(data);

    // Reconectare detectata
    const statusSpan = document.getElementById('status');
    statusSpan.innerText = '🟢 Activ';
    statusSpan.classList.remove('inactive');
    statusSpan.classList.add('active');
    statusSpan.title = 'Suricata este online';
    
    // Daca a fost inactiv, anunță revenirea
    if (wasOffline) {
        showToast('✅ Conexiune restabilită cu Suricata.');
        wasOffline = false;
    }

    } catch (error) {
        console.error("Eroare la preluarea alertelor:", error);

        const statusSpan = document.getElementById('status');
        statusSpan.innerText = '🔴 Inactiv';
        statusSpan.classList.remove('active');
        statusSpan.classList.add('inactive');
        statusSpan.title = 'Suricata sau API-ul nu răspunde';

        // Toast doar o singura data
        if (!wasOffline) {
            showToast('⚠️ Conexiune pierdută cu Suricata!', 'error');
            wasOffline = true;
        }
    }
}

function filterAlerts() {
  const query = document.getElementById('searchInput').value.toLowerCase();
  const filtered = allAlerts.filter(alert =>
    (alert.src_ip || '').toLowerCase().includes(query) ||
    (alert.dest_ip || '').toLowerCase().includes(query) ||
    (alert.proto || '').toLowerCase().includes(query) ||
    (alert.signature || '').toLowerCase().includes(query)
  );
  renderAlerts(filtered);
}

function clearFilter() {
  document.getElementById('searchInput').value = '';
  renderAlerts(allAlerts);
}

function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.classList.add(type === 'error' ? 'toast-error' : 'toast-success');
  toast.innerText = message;

  document.getElementById('toastContainer').appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 500);
  }, 5000);
}

function showTab(tabId) {
  const contents = document.querySelectorAll('.tab-content');
  const buttons = document.querySelectorAll('.tab-button');

  contents.forEach(content => content.classList.remove('active'));
  buttons.forEach(button => button.classList.remove('active'));

  document.getElementById(tabId).classList.add('active');
  document.querySelector(`.tab-button[onclick="showTab('${tabId}')"]`).classList.add('active');

  if (tabId === "devicesTab") {
    loadDevices(); // trigger load devices
  }

  if (tabId === 'statsTab') {
  fetch("http://10.222.8.24:5003/historical_alerts") // IP-ul HP-ului
    .then(response => response.json())
    .then(historicalData => {
      if (Array.isArray(historicalData)) {
        updateChart(historicalData);
        renderTrendChart(historicalData);
      }
    })
    .catch(err => console.error("Eroare la preluarea alertelor istorice:", err));
  }

  if (tabId === 'encodersTab') {
    fetchEncodersInfo();
  }

  if (tabId === 'blockedIPsTab') {
    fetchBlockedIPs();
  }

  if (tabId === 'adminUsersTab') {
    loadUserAlertsUI();
  }

}

function loadDevices() {
  fetch('http://10.222.8.23:5001/devices')
    .then(res => res.json())
    .then(devices => {
      renderDevices(devices);

      const oldMap = new Map(previousDevices.map(d => [d.ip, d])); // schimbat de la mac la ip
      const newMap = new Map(devices.map(d => [d.ip, d]));

      devices.forEach(dev => {
        const name = dev.name || dev.ip;
        const mac = dev.mac;
        const previous = oldMap.get(dev.ip); // comparam dupa IP

        // Marcare dispozitiv nou doar daca are MAC valid si nu era cunoscut
        if (mac && mac !== "-" && mac !== "unknown" && !knownMacs.has(mac)) {
          knownMacs.add(mac);
          showToast(`🆕 Dispozitiv nou: ${name}`, 'success');
        }

        // Notificare revenire online
        if (previous && previous.status === 'offline' && dev.status === 'online') {
          showToast(`✅ ${name} a revenit online`, 'success');
        }

        // Notificare offline
        if (previous && previous.status === 'online' && dev.status === 'offline') {
          showToast(`⚠️ ${name} este acum offline`, 'error');
        }
      });

      previousDevices = devices;
    })
    .catch(err => {
      console.error('Eroare la preluarea dispozitivelor:', err);
    });
}

let autoRefresh = true;
let refreshInterval = setInterval(() => {
  if (autoRefresh) loadAlerts();
}, 10000);

function toggleAutoRefresh() {
  autoRefresh = document.getElementById("autoRefreshToggle").checked;
}

function exportAlertsCSV() {
  const rows = [["Timestamp", "Src IP", "Dest IP", "Protocol", "Signature"]];
  allAlerts.forEach(alert => {
    rows.push([
      alert.timestamp || "-",
      alert.src_ip || "-",
      alert.dest_ip || "-",
      alert.proto || "-",
      alert.signature || "-"
    ]);
  });

  const csvContent = rows.map(e => e.join(",")).join("\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "alerte_suricata.csv";
  link.click();
}

function logout() {
  window.location.href = "/logout";
}

let chart = null;
let trendChart = null;

function updateChart(data) {
    if (!Array.isArray(data)) return;

    const countsByHour = {};

    data.forEach(alert => {
        const date = new Date(alert.timestamp);
        const hourLabel = date.toLocaleString('en-US', {
            month: 'numeric',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        countsByHour[hourLabel] = (countsByHour[hourLabel] || 0) + 1;
    });

    const labels = Object.keys(countsByHour);
    const values = Object.values(countsByHour);

    if (!chart) {
        const ctx = document.getElementById('alertsChart').getContext('2d');
        chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Alerte pe ora',
                    data: values,
                    borderColor: 'cyan',
                    backgroundColor: 'rgba(0, 255, 255, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                animation: false,
                plugins: {
                    legend: {
                        labels: {
                            color: 'cyan'
                        }
                    }
                },
                scales: {
                    x: {
                      ticks: {
                        color: 'white',
                        autoSkip: true,      // afiseaza mai putine etichete
                        maxRotation: 75,
                        minRotation: 45
                      }
                    },
                    y: {
                        ticks: {
                            color: 'white'
                        }
                    }
                }
            }
        });
    } else {
        // NU stergem datele vechi, doar completam daca sunt noi
        labels.forEach((label, index) => {
            const existingIndex = chart.data.labels.indexOf(label);
            if (existingIndex === -1) {
                chart.data.labels.push(label);
                chart.data.datasets[0].data.push(values[index]);
            }
        });

        chart.update();
    }
}

function populateDayDropdown(alerts) {
  const daySelect = document.getElementById('daySelect');
  const selectedDay = daySelect.value; // 👈 salvam selectia curenta

  const days = [...new Set(alerts.map(a => a.timestamp.split('T')[0]))];
  days.sort().reverse(); // cele mai recente sus

  daySelect.innerHTML = '<option value="all">Toate</option>';
  days.forEach(day => {
    const opt = document.createElement('option');
    opt.value = day;
    opt.textContent = day;
    daySelect.appendChild(opt);
  });

  // 👇 restauram selectia anterioara (daca mai exista in lista)
  if ([...daySelect.options].some(opt => opt.value === selectedDay)) {
    daySelect.value = selectedDay;
  } else {
    daySelect.value = "all";
  }

  filterByDay(); // 💡 actualizeaza imediat graficul dupa dropdown
}


function filterByDay() {
  const selectedDay = document.getElementById("daySelect").value;
  if (selectedDay === "all") {
    updateChart(allAlerts);
  } else {
    const filtered = allAlerts.filter(alert => alert.timestamp.startsWith(selectedDay));
    updateChart(filtered);
  }
}

window.addEventListener('load', () => {
  setTimeout(() => {
    const splash = document.getElementById('splashScreen');
    if (splash) splash.remove();
  }, 4000);
  document.getElementById('devicesTab').addEventListener('click', () => {
    loadDevices();
  });
});

async function sendToSHAP() {
  const raw = document.getElementById("shapInput").value;
  try {
    const input = JSON.parse(raw.trim());
    const res = await fetch("http://10.222.8.24:5002/shap_explain", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(input)
    });
    const data = await res.json();

    if (data.error) {
      document.getElementById("shapOutput").innerHTML = `<p style="color:red;">Eroare de la server: ${data.error}</p>`;
      return;
    }

    let html = `<h3>Predictie AI: <span style="color:${data.prediction === 1 ? 'red' : 'lightgreen'}">${["Normal", "Malicious"][data.prediction]}</span></h3>`;
    html += `<table><tr><th>Atribut</th><th>Valoare</th><th>Impact SHAP</th></tr>`;

    data.explanation.forEach(e => {
      html += `
        <tr>
          <td>${e.feature}</td>
          <td>${e.value}</td>
          <td style="color:${e.impact > 0 ? 'red' : 'lightgreen'}">${e.impact.toFixed(4)}</td>
        </tr>`;
    });

    html += `</table>`;
    document.getElementById("shapOutput").innerHTML = html;

    if (data.decoded) {
        const decodedText = `
          <b>Proto decodificat:</b> ${data.decoded.proto}<br>
          <b>Semnatura decodificata:</b> ${data.decoded.signature}
        `;
        document.getElementById("decodedInfo").innerHTML = decodedText;
      }

  } catch (e) {
    document.getElementById("shapOutput").innerHTML = `<p style="color:red;">Eroare JS: ${e}</p>`;
  }
}

function fetchEncodersInfo() {
  fetch("http://10.222.8.24:5002/encoders_info")
    .then(response => response.json())
    .then(data => {
      const container = document.getElementById("encodersList");
      container.innerHTML = "";

      const protoList = Object.entries(data.proto_encoder)
        .map(([key, val]) => `<tr><td>${key}</td><td>${val}</td></tr>`).join("");

      const signatureList = Object.entries(data.signature_encoder)
        .map(([key, val]) => `<tr><td>${key}</td><td>${val}</td></tr>`).join("");

      container.innerHTML = `
        <h3>🧾 Protocol Encodari</h3>
        <table class="tabelXAI"><thead><tr><th>Cod</th><th>Protocol</th></tr></thead><tbody>${protoList}</tbody></table>
        <h3>🧾 Signature Encodari</h3>
        <table class="tabelXAI"><thead><tr><th>Cod</th><th>Semnatura</th></tr></thead><tbody>${signatureList}</tbody></table>
      `;
    })
    .catch(error => {
      console.error("Eroare la fetch /encoders_info:", error);
    });
}

async function fetchBlockedIPs() {
  const res = await fetch('http://10.222.8.24:5003/blocked_ips');
  const data = await res.json();

  const tableBody = document.getElementById("blocked-ips-body");
  tableBody.innerHTML = "";

  data.forEach(entry => {
    const row = `<tr>
      <td>${entry.ip}</td>
      <td>${entry.blocked_at}</td>
      <td>${entry.status === "Blocked" ? "⛔ Blocata" : "✅ Deblocata"}</td>
    </tr>`;
    tableBody.innerHTML += row;
  });
}

function simulateBlock() {
  fetch("http://10.222.8.24:5003/simulate_block", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip: "1.2.3.4" })
  }).then(() => showToast("IP simulat blocat"));
}

function loadUserAlerts() {
  fetch('/user_attacks')
    .then(res => res.json())
    .then(data => {
      const container = document.getElementById('userAttackContainer');
      container.innerHTML = '';

      if (Object.keys(data).length === 0) {
        container.innerHTML = "<p style='color:gray;'>Nu exista alerte inregistrate pentru niciun utilizator.</p>";
        return;
      }

      for (const [user, alerts] of Object.entries(data)) {
        const userSection = document.createElement('div');
        userSection.innerHTML = `<h3 style="color:cyan;">👤 ${user} (${alerts.length} alerte)</h3>`;

        const table = document.createElement('table');
        table.innerHTML = `
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP Sursa</th>
              <th>IP Destinatie</th>
              <th>Protocol</th>
              <th>Semnatura</th>
              <th>Eticheta AI</th>
            </tr>
          </thead>
        `;
        const tbody = document.createElement('tbody');

        alerts.forEach(alert => {
          const row = document.createElement('tr');
          row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td>${alert.src_ip}</td>
            <td>${alert.dest_ip}</td>
            <td>${alert.proto}</td>
            <td>${alert.signature}</td>
            <td>${alert.label}</td>
          `;
          tbody.appendChild(row);
        });

        table.appendChild(tbody);
        userSection.appendChild(table);
        userSection.style.marginBottom = '30px';
        container.appendChild(userSection);
      }
    })
    .catch(err => {
      console.error('Eroare la incarcarea alertelor pe utilizatori:', err);
      document.getElementById('userAttackContainer').innerHTML = "<p style='color:red;'>Eroare la incarcarea alertelor.</p>";
    });
}

function loadAdminUsers() {
  fetch('/admin/user_devices')
    .then(response => response.json())
    .then(data => {
      const container = document.getElementById("userTabsContainer");
      container.innerHTML = '';

      Object.entries(data).forEach(([user, ips]) => {
        if (user === "admin") return; // Omitem adminul complet
        
        const userCard = document.createElement("div");
        userCard.classList.add("user-card");

        const title = document.createElement("h3");
        title.textContent = `👤 ${user}`;
        userCard.appendChild(title);

        if (ips.length > 0) {
          const list = document.createElement("ul");
          ips.forEach(ip => {
            const li = document.createElement("li");
            li.innerHTML = `<span>${ip}</span> <button onclick="unassignIPByClick('${user}', '${ip}')">❌</button>`;
            list.appendChild(li);
          });
          userCard.appendChild(list);
        } else {
          const p = document.createElement("p");
          p.textContent = "Nicio adresa IP asociata.";
          userCard.appendChild(p);
        }

        const deleteBtn = document.createElement("button");
        deleteBtn.textContent = "🗑️ Sterge utilizator";
        deleteBtn.onclick = () => deleteUserByClick(user);
        userCard.appendChild(deleteBtn);

        container.appendChild(userCard);
      });
    });
}

function unassignIPByClick(username, ip) {
  fetch('/admin/unassign_ip', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, ip })
  }).then(loadAdminUsers);
}

function deleteUserByClick(username) {
  fetch('/admin/delete_user', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username })
  }).then(loadAdminUsers);
}

async function loadUserAlertsUI() {
  const res = await fetch('http://10.222.8.24:5000/user_attacks');
  const data = await res.json();

  const tabsContainer = document.getElementById('userTabsContainer');
  const alertsContainer = document.getElementById('userAlertsContainer');
  tabsContainer.innerHTML = '';
  alertsContainer.innerHTML = '';

  Object.keys(data).forEach((username, idx) => {
    const btn = document.createElement('button');
    btn.className = 'tab-button-user';
    btn.innerText = username + ` (${data[username].length} alerte)`;
    btn.onclick = () => renderUserAlerts(data[username], username);
    tabsContainer.appendChild(btn);

    // Auto-load primul user
    if (idx === 0) renderUserAlerts(data[username], username);
  });
}

async function addNewUser() {
  const username = document.getElementById("newUsername").value;
  const password = document.getElementById("newPassword").value;

  const res = await fetch("/admin/add_user", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username, password})
  });

  const data = await res.json();
  alert(data.message || data.error);
}

async function assignIPToUser() {
  const username = document.getElementById("assignUsername").value;
  const ip = document.getElementById("assignIP").value;

  const res = await fetch("/admin/assign_ip", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username, ip})
  });

  const data = await res.json();
  alert(data.message || data.error);
}

async function deleteUser() {
  const username = document.getElementById("deleteUsername").value;

  const res = await fetch("/admin/delete_user", {
    method: "DELETE",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username})
  });

  const data = await res.json();
  alert(data.message || data.error);
}

async function unassignIP() {
  const username = document.getElementById("unassignUsername").value;
  const ip = document.getElementById("unassignIP").value;

  const res = await fetch("/admin/unassign_ip", {
    method: "DELETE",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username, ip})
  });

  const data = await res.json();
  alert(data.message || data.error);
}

function toggleUserManagementPanel() {
  const panel = document.getElementById("userManagementControls");
  panel.style.display = (panel.style.display === "none") ? "block" : "none";
}

function toggleUserControlPanel() {
  const panel = document.getElementById("userViewControls");
  panel.style.display = (panel.style.display === "none") ? "block" : "none";
  if (panel.style.display === "block") {
    loadAdminUsers(); // incarca lista
  } 
}

loadAlerts();
setInterval(loadAlerts, 10000);
loadDevices();
setInterval(loadDevices, 10000);
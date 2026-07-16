const flagsTable = document.getElementById("flags");
const nextPageBtn = document.getElementById("next-page");
const prevPageBtn = document.getElementById("prev-page");
const pageCounter = document.getElementById("page-counter");
const entriesCount = document.getElementById("count");

let page = 0, rows = parseInt(entriesCount.value, 10);

function zeroPad(n, k) {
    let s = `${k}`;
    while (s.length < n) {
        s = "0" + s;
    }
    return s;
}

function changePage(delta) {
    if (page + delta < 0) {
        return;
    }
    page += delta;
    refreshTables();
    pageCounter.textContent = `Page ${zeroPad(2, page+1)}`
}

function buildTableHeader(headers) {
    let html = "<thead><tr>";
    headers.forEach(h => html += `<th class="${h.toLowerCase().replaceAll(' ', '-')}">${h}</th>`);
    html += "</tr></thead>";
    return html;
}

function buildTableRows(data) {
    const statuses = ["🕑", "⌛", "❔", "✅", "⛔"];
    let html = "<tbody>";
    data.forEach(obj => {
        const exploit = DOMPurify.sanitize(obj.exploit);
        const flag = DOMPurify.sanitize(obj.flag);
        const timestamp = new Date(obj.timestamp * 1000).toISOString();
        const submissionTimestamp =
            obj.submissionTimestamp ?
            new Date(obj.submissionTimestamp * 1000).toISOString() : "-";
        const lifetime = Math.round(obj.lifetime);
        const systemMessage = obj.systemMessage ? DOMPurify.sanitize(obj.systemMessage) : "-";
        const status = obj.status != null && obj.status < statuses.length ? statuses[obj.status] : statuses[2];
        entry  = `<td>${status}</td>`;
        entry += `<td>${exploit}</td>`;
        entry += `<td>${flag}</td>`;
        entry += `<td>${timestamp}</td>`;
        entry += `<td>${zeroPad(2, Math.floor(lifetime / 60))}:${zeroPad(2, lifetime % 60)}</td>`;
        entry += `<td>${submissionTimestamp}</td>`;
        entry += `<td>${systemMessage}</td>`;
        html += `<tr>${entry}</tr>`;
    });
    html += "</tbody>";
    return html;
}

function buildTable(data) {
    if (data.length === 0) {
        return "<p> No data to show :( </p>"
    }
    let html = "<table>"
    html += buildTableHeader(["Status", "Exploit", "Flag", "Timestamp", "Lifetime", "Submission Timestamp", "System Message"]);
    html += buildTableRows(data);
    html += "</table>"
    return html;
}

function getJsonFetchErrorType(e) {
    return (e instanceof SyntaxError || e instanceof TypeError || e instanceof DOMException) ? "invalid json" : "connection error";
}

async function refreshTables() {
    try {
        const response = await fetch(`/api/flags?start=${page * rows}&count=${rows}`);
        if (response.status === 200) {
            flagsTable.innerHTML = buildTable(await response.json());
        } else {
            console.log("could not refresh flags table (server error)");
        }
    } catch (error) {
        const type = getJsonFetchErrorType(error);
        console.log(`could not refresh flags table (${type})`);
    }
}

nextPageBtn.addEventListener("click", () => changePage(+1));
prevPageBtn.addEventListener("click", () => changePage(-1));
entriesCount.addEventListener("change", () => {
    newValue = parseInt(entriesCount.value, 10);
    if (newValue < 10) {
        entriesCount.value = newValue = 10;
    }
    rows = newValue;
    refreshTables();
});

const addCheckerButton = document.getElementById("add-checker");
const serviceName = document.getElementById("service");
const portNumber = document.getElementById("port");
const timestampDelta = document.getElementById("delta");
const removeCheckerButton = document.getElementById("remove-checker");
const checkerSelector = document.getElementById("checker-selector");

function isPortValid(port) {
    return (typeof port === "number" && !isNaN(port) && isFinite(port) && port > 0 && port <= 0xffff);
}

function isDeltaValid(delta) {
    return (typeof delta === "number" && !isNaN(delta) && isFinite(delta));
}

function getCheckerName(checker) {
    const service = DOMPurify.sanitize(checker.service);
    const port = parseInt(checker.port);
    const delta = parseInt(checker.delta);
    if (isPortValid(port) && isDeltaValid(delta) && service.length > 0) {
        return `${DOMPurify.sanitize(service)} (${port}) - ${delta}`;
    }
    return null;
}

function rebuildSelectorList(data) {
    // store the currently selected value
    const selectedIndex = checkerSelector.selectedIndex;
    const selectedValue = selectedIndex < 0 ? NaN : parseInt(checkerSelector.children[selectedIndex].value);
    checkerSelector.innerHTML = '<option value="" disabled hidden selected>Select a checker</option>';
    data.forEach(checker => {
        const name = getCheckerName(checker);
        if (!name) {
            // invalid checker name, skip
            return;
        }
        const value = checker.delta;
        const element = document.createElement("option");
        element.value = `${value}`;
        element.textContent = name;
        // TODO: switch to replaceChildren() maybe?
        checkerSelector.appendChild(element);
        if (value === selectedValue) {
            checkerSelector.selectedIndex = checkerSelector.childElementCount - 1;
        }
    });
}

removeCheckerButton.addEventListener("click", async () => {
    const selectedIndex = checkerSelector.selectedIndex;
    if (selectedIndex <= 0) {
        return;
    }
    const selectedValue = parseInt(checkerSelector.children[selectedIndex].value);
    try {
        const response = await fetch("/api/hfi", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "remove": true,
                "delta": selectedValue
            })
        });
        if (response.status === 200) {
            rebuildSelectorList(await response.json());
        } else {
            alert("could not remove checker (server error)");
        }
    } catch (error) {
        const type = getJsonFetchErrorType(error);
        alert(`could not remove checker (${type})`);
    }
});

addCheckerButton.addEventListener("click", async () => {
    const service = serviceName.value;
    const port = parseInt(portNumber.value);
    const delta = parseInt(timestampDelta.value);

    if (!isPortValid(port)) {
        alert("port number must be a valid integer");
        return;
    }
    if (!isDeltaValid(delta)) {
        alert("timestamp delta must be a valid integer");
        return;
    }
    if (service.length === 0) {
        alert("service name must not be nothing");
        return;
    }

    try {
        const response = await fetch("/api/hfi", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "service": service,
                "port": port,
                "delta": delta
            })
        });
        if (response === 200) {
            rebuildSelectorList(await response.json());
        } else {
            alert("could not add checker (server error)");
        }
    } catch (error) {
        const type = getJsonFetchErrorType(error);
        alert(`could not add checker (${type})`);
    }
});

async function refreshSelector() {
    try {
        const response = await fetch("/api/hfi");
        if (response.status === 200) {
            rebuildSelectorList(await response.json());
        } else {
            console.log("could not refresh selector (server error)");
        }
    } catch (error) {
        const type = getJsonFetchErrorType(error);
        console.log(`could not refresh selector (${type})`)
    }
}

async function refreshAll() {
    await refreshTables();
    await refreshSelector();
}

setInterval(refreshAll, 5000);
refreshAll();

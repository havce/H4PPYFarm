const flags_table = document.getElementById("flags");
const next_page_btn = document.getElementById("next-page");
const prev_page_btn = document.getElementById("prev-page");
const page_counter = document.getElementById("page-counter");
const entries_count = document.getElementById("count");

let page = 0, rows = parseInt(entries_count.value, 10);

function zero_pad(n, k) {
    let s = `${k}`;
    while (s.length < n) {
        s = "0" + s;
    }
    return s;
}

function change_page(delta) {
    if (page + delta < 0) {
        console.log(page);
        return;
    }
    page += delta;
    refresh_tables();
    page_counter.textContent = `Page ${zero_pad(2, page+1)}`
}

function build_table_header(headers) {
    let html = "<thead><tr>";
    headers.forEach(h => html += `<th class="${h.toLowerCase().replaceAll(' ', '-')}">${h}</th>`);
    html += "</tr></thead>";
    return html;
}

function build_table_rows(data) {
    const statuses = ["🕑", "⌛", "❔", "✅", "⛔"];
    let html = "<tbody>";
    data.forEach(obj => {
        const exploit = DOMPurify.sanitize(obj.exploit);
        const flag = DOMPurify.sanitize(obj.flag);
        const timestamp = new Date(obj.timestamp * 1000).toISOString();
        const submission_timestamp =
            obj.submission_timestamp ?
            new Date(obj.submission_timestamp * 1000).toISOString() : "-";
        const lifetime = Math.round(obj.lifetime);
        const system_message = obj.system_message ? DOMPurify.sanitize(obj.system_message) : "-";
        const status = obj.status != null && obj.status < statuses.length ? statuses[obj.status] : statuses[2];
        entry  = `<td>${status}</td>`;
        entry += `<td>${exploit}</td>`;
        entry += `<td>${flag}</td>`;
        entry += `<td>${timestamp}</td>`;
        entry += `<td>${zero_pad(2, Math.floor(lifetime / 60))}:${zero_pad(2, lifetime % 60)}</td>`;
        entry += `<td>${submission_timestamp}</td>`;
        entry += `<td>${system_message}</td>`;
        html += `<tr>${entry}</tr>`;
    });
    html += "</tbody>";
    return html;
}

function build_table(data) {
    if (data.length === 0) {
        return "<p> No data to show :( </p>"
    }
    let html = "<table>"
    html += build_table_header(["Status", "Exploit", "Flag", "Timestamp", "Lifetime", "Submission Timestamp", "System Message"]);
    html += build_table_rows(data);
    html += "</table>"
    return html;
}

function refresh_tables() {
    fetch(`/api/flags?start=${page * rows}&count=${rows}`)
        .then(res => res.json(), () => [])
        .then(data => flags_table.innerHTML = build_table(data));
}

next_page_btn.addEventListener("click", () => change_page(+1));
prev_page_btn.addEventListener("click", () => change_page(-1));
entries_count.addEventListener("change", () => {
    new_value = parseInt(entries_count.value, 10);
    if (new_value < 10) {
        entries_count.value = new_value = 10;
    }
    rows = new_value;
    refresh_tables();
});

const add_checker_button = document.getElementById("add-checker");
const service_name = document.getElementById("service");
const port_number = document.getElementById("port");
const timestamp_delta = document.getElementById("delta");
const remove_checker_button = document.getElementById("remove-checker");
const checker_selector = document.getElementById("checker-selector");

function is_port_valid(port) {
    return (typeof port === "number" && !isNaN(port) && isFinite(port) && port > 0 && port <= 0xffff);
}

function is_delta_valid(delta) {
    return (typeof delta === "number" && !isNaN(delta) && isFinite(delta));
}

function get_checker_name(checker) {
    const service = DOMPurify.sanitize(checker.service);
    const port = parseInt(checker.port);
    const delta = parseInt(checker.delta);
    if (is_port_valid(port) && is_delta_valid(delta) && service.length > 0) {
        return `${DOMPurify.sanitize(service)} (${port}) - ${delta}`;
    }
    return null;
}

function rebuild_selector_list(data) {
    // store the currently selected value
    const selected_index = checker_selector.selectedIndex;
    const selected_value = selected_index < 0 ? NaN : parseInt(checker_selector.children[selected_index].value);
    checker_selector.innerHTML = '<option value="" disabled hidden selected>Select a checker</option>';
    data.forEach(checker => {
        const name = get_checker_name(checker);
        if (!name) {
            // invalid checker name, skip
            return;
        }
        const value = checker.delta;
        const elem = document.createElement("option");
        elem.value = `${value}`;
        elem.textContent = name;
        // TODO: switch to replaceChildren() maybe?
        checker_selector.appendChild(elem);
        if (value === selected_value) {
            checker_selector.selectedIndex = checker_selector.childElementCount - 1;
        }
    });
}

remove_checker_button.addEventListener("click", () => {
    const selected_index = checker_selector.selectedIndex;
    if (selected_index <= 0) {
        return;
    }
    const selected_value = parseInt(checker_selector.children[selected_index].value);
    fetch("/api/hfi", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            "remove": true,
            "delta": selected_value
        })
    })
        .then(res => res.json(), () => {
            alert("could not remove checker (server error)");
            return [];
        })
        .then(
            data => rebuild_selector_list(data),
            () => {
                alert("could not remove checker (invalid server response)");
            }
        );
});

add_checker_button.addEventListener("click", () => {
    const service = service_name.value;
    const port = parseInt(port_number.value);
    const delta = parseInt(timestamp_delta.value);

    if (!is_port_valid(port)) {
        alert("port number must be a valid integer");
        return;
    }

    if (!is_delta_valid(delta)) {
        alert("timestamp delta must be a valid integer");
        return;
    }

    if (service.length === 0) {
        alert("service name must not be nothing");
        return;
    }

    fetch("/api/hfi", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            "service": service,
            "port": port,
            "delta": delta
        })
    })
        .then(res => res.json(), () => {
            alert("could not add checker (server error)");
            return [];
        })
        .then(
            data => rebuild_selector_list(data),
            () => {
                alert("could not add checker (invalid server response)");
            }
        );
});

function refresh_selector() {
    fetch("/api/hfi")
        .then(res => res.json(), () => [])
        .then(data => {
            rebuild_selector_list(data);
        })
}

function refresh_all() {
    refresh_tables();
    refresh_selector();
}

setInterval(refresh_all, 5000);
refresh_all();

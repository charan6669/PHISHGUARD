async function scanURL() {

    const input =
        document.getElementById("urlInput");

    const button =
        document.getElementById("scanButton");

    const title =
        document.getElementById("resultTitle");

    const message =
        document.getElementById("resultMessage");

    const score =
        document.getElementById("riskScore");

    const reasonsBox =
        document.getElementById("reasons");


    const url = input.value.trim();


    if (!url) {

        title.textContent = "URL REQUIRED";

        message.textContent =
            "Enter a URL to start scanning.";

        score.textContent = "--";

        return;
    }


    button.disabled = true;

    button.textContent = "Scanning...";


    try {

        const response = await fetch(
            "/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


        const data =
            await response.json();


        if (data.error) {

            title.textContent =
                "LOGIN REQUIRED";

            message.textContent =
                "Please login again.";

            return;
        }


        title.textContent =
            data.status;

        score.textContent =
            data.score + "%";


        if (data.status === "SAFE") {

            message.textContent =
                "No major phishing indicators detected.";

        }

        else if (
            data.status === "SUSPICIOUS"
        ) {

            message.textContent =
                "Potentially suspicious indicators detected.";

        }

        else {

            message.textContent =
                "High-risk phishing indicators detected.";

        }


        reasonsBox.innerHTML = "";


        data.reasons.forEach(
            function(reason) {

                const div =
                    document.createElement("div");

                div.className = "reason";

                div.textContent = reason;

                reasonsBox.appendChild(div);

            }
        );


        loadHistory();

    }

    catch(error) {

        title.textContent =
            "ERROR";

        message.textContent =
            "Unable to connect to scanner.";

    }


    button.disabled = false;

    button.textContent =
        "Scan URL →";
}


async function loadHistory() {

    const container =
        document.getElementById(
            "historyList"
        );


    try {

        const response =
            await fetch("/history");

        const data =
            await response.json();


        if (!data.length) {

            container.innerHTML =
                `<div class="empty-history">
                    No scans yet.
                </div>`;

            return;
        }


        container.innerHTML = "";


        data.forEach(
            function(item) {

                const div =
                    document.createElement("div");

                div.className =
                    "history-item";


                div.innerHTML = `

                    <div>

                        <div class="history-url">
                            ${escapeHTML(item.url)}
                        </div>

                        <div class="history-time">
                            ${item.time}
                        </div>

                    </div>


                    <div>

                        <div class="history-status">
                            ${item.status}
                            ·
                            ${item.score}%
                        </div>

                    </div>

                `;


                container.appendChild(div);

            }
        );

    }

    catch(error) {

        container.innerHTML =
            `<div class="empty-history">
                Unable to load history.
            </div>`;

    }

}


function escapeHTML(text) {

    const div =
        document.createElement("div");

    div.textContent = text;

    return div.innerHTML;
}


loadHistory();
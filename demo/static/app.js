const chatBox = document.getElementById('chatBox');
const userInput = document.getElementById('userInput');
const sendBtn = document.getElementById('sendBtn');
const inputLogs = document.getElementById('inputLogs');
const outputLogs = document.getElementById('outputLogs');

function appendMessage(sender, text, isBlocked = false) {
    const div = document.createElement('div');
    div.classList.add('message');
    if (sender === 'user') {
        div.classList.add('user-msg');
    } else {
        div.classList.add('agent-msg');
        if (isBlocked) div.classList.add('blocked');
    }
    div.innerText = text;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function appendLog(element, text) {
    if (element.innerHTML.includes("Waiting for")) {
        element.innerHTML = '';
    }
    const div = document.createElement('div');
    div.classList.add('log-line');
    
    // Colorize based on content
    if (text.includes('[BLOCKED]') || text.includes('[WARNING]')) {
        div.classList.add('text-danger');
    } else if (text.includes('[PASSED]')) {
        div.classList.add('text-success');
    } else {
        div.classList.add('text-info');
    }
    
    // Prefix with timestamp
    const time = new Date().toLocaleTimeString();
    div.innerText = `[${time}] ${text}`;
    element.appendChild(div);
    element.scrollTop = element.scrollHeight;
}

async function sendMessage() {
    const text = userInput.value.trim();
    if (!text) return;

    appendMessage('user', text);
    userInput.value = '';
    
    // Clear logs for new request
    inputLogs.innerHTML = '';
    outputLogs.innerHTML = '';
    appendLog(inputLogs, 'New request received...');

    // Loading indicator
    const loadingId = 'loading-' + Date.now();
    const loadingDiv = document.createElement('div');
    loadingDiv.id = loadingId;
    loadingDiv.classList.add('message', 'agent-msg');
    loadingDiv.innerText = 'Analyzing guardrails & processing...';
    chatBox.appendChild(loadingDiv);
    chatBox.scrollTop = chatBox.scrollHeight;

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: text })
        });
        
        const data = await response.json();
        
        // Remove loading
        document.getElementById(loadingId).remove();
        
        // Render logs
        data.input_logs.forEach(log => appendLog(inputLogs, log));
        data.output_logs.forEach(log => appendLog(outputLogs, log));
        
        if (data.output_logs.length === 0) {
             appendLog(outputLogs, 'No model output (Request was blocked).');
        }

        // Render response
        const isBlocked = data.status === 'blocked';
        appendMessage('agent', data.response, isBlocked);
        
    } catch (err) {
        document.getElementById(loadingId).remove();
        appendMessage('agent', 'System Error: Could not connect to API.', true);
        console.error(err);
    }
}

function setPrompt(text) {
    userInput.value = text;
    userInput.focus();
}

sendBtn.addEventListener('click', sendMessage);
userInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
});

/**
 * VANT-SIEM Chat Widget - Optimized Version
 * Enhanced with performance improvements, error handling, and accessibility features
 */


class ChatWidget {
    constructor() {
        this.chatVisible = false;
        this.chatHistory = [];
        this.isTyping = false;
        this.connectionState = 'disconnected'; // 'connecting', 'connected', 'error'
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 3;
        this.messageQueue = [];
        this.isProcessingQueue = false;

        // Configuration
        this.config = {
            maxHistoryLength: 50,
            maxMessageLength: 1000,
            debounceDelay: 300,
            maxRetries: 3,
            retryDelay: 1000,
            reconnectDelay: 2000
        };

        this.init();
        this.bindEvents();
        this.showQuickSuggestions();
    }

    init() {
        // Initialize DOM elements
        this.widget = document.getElementById("chatWidget");
        this.toggleBtn = document.getElementById("chatToggleBtn");
        this.closeBtn = document.getElementById("chatCloseBtn");
        this.messagesContainer = document.getElementById("chatMessages");
        this.input = document.getElementById("chatInput");
        this.sendButton = document.getElementById("sendButton");
        this.statusDiv = document.getElementById("chatStatus");

        // Initialize widget state
        if (this.widget) {
            this.widget.classList.remove('visible');
        }

        // Ensure initial state - hide widget, show toggle button
        if (this.widget) {
            this.widget.classList.remove('visible');
        }

        if (this.toggleBtn) {
            this.toggleBtn.style.display = 'flex';
        }

        // Set initial state
        this.updateConnectionStatus('connected');
    }

    bindEvents() {
        // Toggle chat
        if (this.toggleBtn) {
            this.toggleBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.show();
            });
        }

        // Close chat
        if (this.closeBtn) {
            this.closeBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.hide();
            });
        }

        // Send message events
        if (this.sendButton) {
            this.sendButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.sendMessage();
            });
        }

        if (this.input) {
            // Enter to send, Shift+Enter for new line
            this.input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });

            // Debounced input handling
            let inputTimeout;
            this.input.addEventListener('input', () => {
                clearTimeout(inputTimeout);
                inputTimeout = setTimeout(() => {
                    this.handleInputChange();
                }, this.config.debounceDelay);
            });
        }

        // Global keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Escape to close chat
            if (e.key === 'Escape' && this.chatVisible) {
                this.toggleChat();
            }

            // Ctrl+/ to focus chat
            if (e.ctrlKey && e.key === '/') {
                e.preventDefault();
                if (!this.chatVisible) this.toggleChat();
                if (this.input) this.input.focus();
            }
        });

        // Click outside to close
        document.addEventListener('click', (e) => {
            if (this.chatVisible && this.widget && this.toggleBtn &&
                !this.widget.contains(e.target) && !this.toggleBtn.contains(e.target)) {
                this.toggleChat();
            }
        });

        // Touch gestures for mobile
        this.bindTouchGestures();

        // Window resize handling
        window.addEventListener('resize', () => this.handleResize());
    }

    bindTouchGestures() {
        let startX, startY;

        document.addEventListener('touchstart', (e) => {
            startX = e.touches[0].clientX;
            startY = e.touches[0].clientY;
        }, { passive: true });

        document.addEventListener('touchend', (e) => {
            if (!startX || !startY) return;

            const endX = e.changedTouches[0].clientX;
            const endY = e.changedTouches[0].clientY;
            const deltaX = startX - endX;
            const deltaY = startY - endY;

            // Swipe left/right to close (more than 100px horizontal movement)
            if (Math.abs(deltaX) > 100 && Math.abs(deltaY) < 50) {
                this.toggleChat();
            }

            startX = startY = null;
        }, { passive: true });
    }

    handleResize() {
        // Adjust chat position on mobile
        if (window.innerWidth <= 480 && this.chatVisible) {
            // Ensure chat doesn't go off-screen
            const rect = this.widget.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
                this.widget.style.right = '10px';
            }
        }
    }

    toggleChat() {
        this.chatVisible = !this.chatVisible;

        if (this.widget && this.toggleBtn) {
            if (this.chatVisible) {
                this.widget.style.setProperty('display', 'flex', 'important');
                this.toggleBtn.style.display = 'none';
                this.clearNotifications();

                // Focus input after animation
                setTimeout(() => {
                    if (this.input) this.input.focus();
                }, 100);

                // Mark messages as read
                this.markMessagesAsRead();
            } else {
                this.widget.style.setProperty('display', 'none', 'important');
                this.toggleBtn.style.display = 'flex';
            }
        }
    }

    sendMessage() {
        if (!this.input) return;

        const message = this.sanitizeInput(this.input.value.trim());

        if (!message || this.isTyping) return;

        // Add user message
        this.addMessage(message, 'user');
        this.chatHistory.push({ role: 'user', content: message });

        // Limit history
        if (this.chatHistory.length > this.config.maxHistoryLength) {
            this.chatHistory = this.chatHistory.slice(-this.config.maxHistoryLength);
        }

        // Clear input
        this.input.value = '';
        this.handleInputChange(); // Update UI

        // Show typing indicator
        this.showTypingIndicator();

        // Send to AI with retry logic
        this.sendToAI(message);
    }

    sanitizeInput(input) {
        if (!input) return '';

        return input
            .replace(/[<>]/g, '') // Remove potential HTML tags
            .replace(/\s+/g, ' ') // Normalize whitespace
            .trim()
            .substring(0, this.config.maxMessageLength);
    }

    handleInputChange() {
        if (!this.input || !this.sendButton) return;

        const hasContent = this.input.value.trim().length > 0;
        this.sendButton.disabled = !hasContent;

        // Auto-resize textarea
        this.input.style.height = 'auto';
        this.input.style.height = Math.min(this.input.scrollHeight, 100) + 'px';
    }

    async sendToAI(message) {
        // Add to queue for processing
        this.messageQueue.push(message);
        this.processQueue();
    }

    async processQueue() {
        if (this.isProcessingQueue || this.messageQueue.length === 0) return;

        this.isProcessingQueue = true;

        while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift();
            await this.sendMessageWithRetry(message);
        }

        this.isProcessingQueue = false;
    }

    async sendMessageWithRetry(message, attempt = 1) {
        try {
            this.updateConnectionStatus('connecting');

            const response = await this.makeAPIRequest(message);

            if (response.success) {
                this.hideTypingIndicator();
                this.addMessage(response.response, 'bot');
                this.chatHistory.push({ role: 'assistant', content: response.response });
                this.updateConnectionStatus('connected');

                // Track successful interaction
                this.trackEvent('message_sent', {
                    length: message.length,
                    response_length: response.response.length
                });

            } else {
                throw new Error(response.error || 'Unknown error');
            }

        } catch (error) {
            console.error('Chat API Error:', error);

            if (attempt < this.config.maxRetries) {
                // Exponential backoff
                const delay = Math.pow(2, attempt) * this.config.retryDelay;
                setTimeout(() => {
                    this.sendMessageWithRetry(message, attempt + 1);
                }, delay);
            } else {
                this.hideTypingIndicator();
                this.addMessage(`❌ Error: ${error.message}. Por favor intenta de nuevo.`, 'bot');
                this.updateConnectionStatus('error');

                // Track error
                this.trackEvent('message_error', {
                    error: error.message,
                    attempts: attempt
                });
            }
        }
    }

    async makeAPIRequest(message) {
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]')?.value;

        const response = await fetch('/siem/dashboard/api/analysis/ollama/chat/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({
                message: message,
                history: this.chatHistory.slice(-10), // Last 10 messages for context
            }),
        });

        return await response.json();
    }

    addMessage(content, sender = 'bot') {
        if (!this.messagesContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;

        const avatar = sender === 'bot' ? '' : '<i class="fas fa-user"></i>';
        const time = new Date().toLocaleTimeString('es-ES', {
            hour: '2-digit',
            minute: '2-digit',
        });

        messageDiv.innerHTML = `
            <div class="message-avatar">${avatar}</div>
            <div class="message-content">
                <div class="message-text">${this.escapeHtml(content)}</div>
                <div class="message-time">${time}</div>
            </div>
        `;

        this.messagesContainer.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addHtmlMessage(content, sender = 'bot') {
        if (!this.messagesContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;

        const avatar = sender === 'bot' ? '' : '<i class="fas fa-user"></i>';
        const time = new Date().toLocaleTimeString('es-ES', {
            hour: '2-digit',
            minute: '2-digit',
        });

        messageDiv.innerHTML = `
            <div class="message-avatar">${avatar}</div>
            <div class="message-content">
                <div class="message-text">${content}</div>
                <div class="message-time">${time}</div>
            </div>
        `;

        this.messagesContainer.appendChild(messageDiv);
        this.scrollToBottom();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showTypingIndicator() {
        if (!this.messagesContainer || this.isTyping) return;

        this.isTyping = true;
        const indicator = document.createElement('div');
        indicator.className = 'typing-indicator';
        indicator.id = 'typingIndicator';

        indicator.innerHTML = `
            <div class="message-avatar"></div>
            <div class="message-content">
                <div class="loading-dots">
                    <span></span><span></span><span></span>
                </div>
                <div class="loading-text">VANT-AI está analizando...</div>
            </div>
        `;

        this.messagesContainer.appendChild(indicator);
        this.scrollToBottom();
    }

    hideTypingIndicator() {
        this.isTyping = false;
        const indicator = document.getElementById('typingIndicator');
        if (indicator) {
            indicator.remove();
        }
    }

    scrollToBottom(smooth = true) {
        if (!this.messagesContainer) return;

        // Check if user is near bottom before auto-scrolling
        const isNearBottom = this.isUserNearBottom();

        if (smooth && isNearBottom) {
            this.messagesContainer.lastElementChild?.scrollIntoView({
                behavior: 'smooth',
                block: 'end'
            });
        } else if (!smooth) {
            this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
        }
    }

    isUserNearBottom() {
        if (!this.messagesContainer) return true;

        const threshold = 100; // pixels from bottom
        return this.messagesContainer.scrollHeight - this.messagesContainer.scrollTop - this.messagesContainer.clientHeight < threshold;
    }

    updateConnectionStatus(status) {
        this.connectionState = status;

        if (!this.statusDiv) return;

        let statusHtml = '';
        switch (status) {
            case 'connected':
                statusHtml = '<small class="text-muted"><i class="fas fa-circle text-success me-1"></i>Conectado</small>';
                break;
            case 'connecting':
                statusHtml = '<small class="text-muted"><i class="fas fa-circle text-warning me-1"></i>Conectando...</small>';
                break;
            case 'error':
                statusHtml = '<small class="text-muted"><i class="fas fa-circle text-danger me-1"></i>Error de conexión</small>';
                break;
            default:
                statusHtml = '<small class="text-muted"><i class="fas fa-circle text-secondary me-1"></i>Desconectado</small>';
        }

        this.statusDiv.innerHTML = statusHtml;
    }

    clearNotifications() {
        const badge = document.getElementById('chatNotificationBadge');
        if (badge) {
            badge.style.display = 'none';
            badge.textContent = '0';
        }
    }

    addNotification() {
        const badge = document.getElementById('chatNotificationBadge');
        if (badge) {
            let count = parseInt(badge.textContent || '0') + 1;
            badge.textContent = count;
            badge.style.display = 'flex';
        }
    }

    markMessagesAsRead() {
        // Mark all messages as read (could integrate with backend)
        this.clearNotifications();
    }

    showQuickSuggestions() {
        setTimeout(() => {
            const suggestions = [
                '¿Estado actual del sistema?',
                'Analizar alertas recientes',
                'Generar reporte automático',
                'Revisar incidentes activos',
            ];

            let suggestionsHtml = '💡 <strong>Sugerencias de consulta:</strong><br><br>';
            suggestions.forEach((suggestion, index) => {
                suggestionsHtml += `<button class="btn btn-sm btn-outline-info me-2 mb-2" onclick="chatWidget.useSuggestion('${this.escapeHtml(suggestion)}')">${suggestion}</button>`;
                if ((index + 1) % 2 === 0) suggestionsHtml += '<br>';
            });

            this.addHtmlMessage(suggestionsHtml, 'bot');
        }, 3000);
    }

    useSuggestion(suggestion) {
        if (this.input) {
            this.input.value = suggestion;
            this.sendMessage();
        }
    }

    trackEvent(eventType, data) {
        // Analytics tracking (could send to backend)
        console.log('Chat Event:', eventType, data);

        // Could implement actual tracking:
        // fetch('/api/analytics/', { method: 'POST', body: JSON.stringify({ event: eventType, data }) });
    }

    checkCSSLoaded() {
        // Check if our CSS is loaded by testing a computed style
        const testEl = document.createElement('div');
        testEl.className = 'chat-widget';
        testEl.style.display = 'none';
        document.body.appendChild(testEl);

        const computedStyle = window.getComputedStyle(testEl);
        const isCSSLoaded = computedStyle.position === 'fixed';

        document.body.removeChild(testEl);
        return isCSSLoaded;
    }

    // Public API for external access
    show() {
        if (!this.chatVisible) {
            this.toggleChat();
        }
    }

    hide() {
        if (this.chatVisible) this.toggleChat();
    }

    send(message) {
        if (this.input) {
            this.input.value = message;
            this.sendMessage();
        }
    }
}

// Initialize when DOM is ready
let chatWidget;
document.addEventListener('DOMContentLoaded', () => {
    try {
        chatWidget = new ChatWidget();
        // Make it globally available for suggestions
        window.chatWidget = chatWidget;
    } catch (error) {
        console.error('ChatWidget initialization failed:', error);
    }
});

// Fallback initialization in case DOMContentLoaded already fired
if (document.readyState !== 'loading') {
    try {
        if (!chatWidget) {
            chatWidget = new ChatWidget();
            window.chatWidget = chatWidget;
        }
    } catch (error) {
        console.error('ChatWidget fallback initialization failed:', error);
    }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ChatWidget;
}
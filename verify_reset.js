/**
 * Handles password complexity validation and form submission for the reset verification page.
 */
document.addEventListener('DOMContentLoaded', function() {
    const togglePassword = document.querySelector('#togglePassword');
    const toggleConfirmPassword = document.querySelector('#toggleConfirmPassword');
    const passwordInput = document.getElementById('passwordField');
    const confirmInput = document.getElementById('confirmPasswordField');
    const matchFeedback = document.getElementById('matchFeedback');
    const passwordRules = document.getElementById('passwordRules');
    const verifyForm = document.getElementById('verifyResetForm');
    const overlay = document.getElementById('processingOverlay');



    const rules = {
        length: { el: document.getElementById('rule-length'), regex: /.{8,}/, label: 'At least 8 characters' },
        upper: { el: document.getElementById('rule-upper'), regex: /[A-Z]/, label: 'At least One Uppercase Letter' },
        lower: { el: document.getElementById('rule-lower'), regex: /[a-z]/, label: 'At least One Lowercase Letter' },
        number: { el: document.getElementById('rule-number'), regex: /[0-9]/, label: 'At least One Number' },
        special: { el: document.getElementById('rule-special'), regex: /[\W_]/, label: 'At least One Special Symbol' }
    };

    if (passwordInput) {
        passwordInput.addEventListener('focus', () => { 
            if (passwordRules) passwordRules.style.display = 'flex'; 
        });
        passwordInput.addEventListener('blur', () => { 
            if (passwordRules) passwordRules.style.display = 'none'; 
        });

        passwordInput.addEventListener('input', validatePassword);
    }

    if (confirmInput) {
        confirmInput.addEventListener('input', validateMatch);
    }

    function validatePassword() {
        if (!passwordInput) return false;
        const val = passwordInput.value;
        if (val.length > 0 && passwordRules) passwordRules.style.display = 'flex';
        
        let allValid = true;
        for (const key in rules) {
            const rule = rules[key];
            if (!rule.el) continue;

            if (rule.regex.test(val)) {
                rule.el.classList.remove('auth-invalid-rule');
                rule.el.classList.add('auth-valid-rule');
                rule.el.innerHTML = '<i class="fa-solid fa-check"></i> ' + rule.label;
            } else {
                rule.el.classList.remove('auth-valid-rule');
                rule.el.classList.add('auth-invalid-rule');
                rule.el.innerHTML = '● ' + rule.label;
                allValid = false;
            }
        }
        validateMatch();
        return allValid;
    }

    function validateMatch() {
        if (!passwordInput || !confirmInput || !matchFeedback) return false;
        
        const pass = passwordInput.value;
        const confirm = confirmInput.value;
        
        if (!confirm) { 
            matchFeedback.textContent = ''; 
            return false; 
        }

        if (pass === confirm) {
            matchFeedback.textContent = 'Passwords Match';
            matchFeedback.style.color = '#00ff88';
            return true;
        } else {
            matchFeedback.textContent = 'Passwords Do Not Match';
            matchFeedback.style.color = '#ff4444';
            return false;
        }
    }

    function checkFormState() {
        const isPassValid = validatePassword();
        const isMatchValid = validateMatch();
        const btn = verifyForm.querySelector('button');
        if (btn) {
            btn.disabled = !(isPassValid && isMatchValid);
            btn.style.opacity = btn.disabled ? "0.5" : "1";
            btn.style.cursor = btn.disabled ? "not-allowed" : "pointer";
        }
    }

    if (passwordInput) {
        passwordInput.addEventListener('input', checkFormState);
    }
    if (confirmInput) {
        confirmInput.addEventListener('input', checkFormState);
    }

    // Initial check
    checkFormState();

    if (verifyForm && overlay) {
        verifyForm.addEventListener('submit', function (e) {
            // 1. Check browser validity
            if (!this.checkValidity()) {
                return;
            }

            const isPassValid = validatePassword();
            const isMatchValid = validateMatch();

            if (!isPassValid || !isMatchValid) {
                e.preventDefault();
                alert('Please ensure all password requirements are met.');
            } else {
                e.preventDefault();
                overlay.classList.add('visible');
                document.body.style.overflow = 'hidden';
                
                const btn = this.querySelector('button');
                if (btn) btn.disabled = true;
                
                this.submit();
            }
        });
    }
});

/**
 * Handles the password reset request form submission with animation.
 */
document.addEventListener('DOMContentLoaded', function() {
    const resetForm = document.getElementById('resetRequestForm');
    const overlay = document.getElementById('processingOverlay');

    if (resetForm && overlay) {
        resetForm.addEventListener('submit', function (e) {
            // 1. Check browser validity (prevents animation freezing if form is incomplete)
            if (!this.checkValidity()) {
                return; // Let browser show validation bubbles
            }

            e.preventDefault();
            
            // Show the animation overlay
            overlay.classList.add('visible');
            document.body.style.overflow = 'hidden';
            
            // Disable the submit button to prevent double-clicks
            const btn = this.querySelector('button');
            if (btn) btn.disabled = true;
            
            // Submit immediately, page will naturally redirect
            this.submit(); 
        });
    }
});

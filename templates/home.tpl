<div class="container">
    <div class="header">
        <h1><?= htmlspecialchars($siteName ?? 'Webradio Verwaltungssystem') ?></h1>
        <p><?= htmlspecialchars($siteDescription ?? 'Professionelle Webradio-Verwaltung') ?></p>
        
        <?php if ($isLoggedIn): ?>
            <div class="user-info">
                <p>Willkommen, <strong><?= htmlspecialchars($username) ?></strong>!</p>
                <div class="actions">
                    <a href="?route=dashboard" class="btn">Dashboard</a>
                    <a href="?route=profile" class="btn secondary">Profil</a>
                    <a href="?route=logout" class="btn secondary">Abmelden</a>
                </div>
            </div>
        <?php else: ?>
            <div class="login-prompt">
                <p>Melden Sie sich an, um das System zu verwenden.</p>
                <div class="actions">
                    <a href="?route=login" class="btn">Anmelden</a>
                    <a href="?route=register" class="btn secondary">Registrieren</a>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <div class="features">
        <div class="feature-card">
            <h3>Benutzerverwaltung</h3>
            <p>Verwalten Sie Hörer und Administratoren Ihres Webradios.</p>
        </div>
        
        <div class="feature-card">
            <h3>Modulsteuerung</h3>
            <p>Aktivieren und konfigurieren Sie Module nach Bedarf.</p>
        </div>
        
        <div class="feature-card">
            <h3>Berechtigungen</h3>
            <p>Granulare Rechteverwaltung für alle Systemfunktionen.</p>
        </div>
    </div>
</div>

<style>
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { text-align: center; margin-bottom: 40px; }
.header h1 { font-size: 2.5em; margin-bottom: 10px; color: #004e92; }
.user-info, .login-prompt { margin: 20px 0; }
.actions { margin-top: 15px; }
.btn { 
    display: inline-block; 
    padding: 10px 20px; 
    margin: 5px; 
    background: #004e92; 
    color: white; 
    text-decoration: none; 
    border-radius: 5px; 
}
.btn.secondary { background: #666; }
.btn:hover { opacity: 0.8; }
.features { 
    display: grid; 
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
    gap: 20px; 
    margin-top: 40px; 
}
.feature-card { 
    background: #f9f9f9; 
    padding: 20px; 
    border-radius: 8px; 
    text-align: center; 
}
</style>
<?php
class HomeController {
    private Database $database;
    private Template $template;
    private Auth $auth;

    public function __construct(Database $database, Template $template, Auth $auth) {
        $this->database = $database;
        $this->template = $template;
        $this->auth = $auth;
    }

    public function index(): void {
        // Template-Variablen setzen
        $this->template->assign('pageTitle', 'Webradio Verwaltungssystem');
        $this->template->assign('siteName', $this->database->getSetting('system', 'site_name', 'Webradio System'));
        $this->template->assign('siteDescription', $this->database->getSetting('system', 'site_description', 'Professionelle Webradio-Verwaltung'));
        
        // Benutzer-spezifische Daten
        if ($this->auth->isLoggedIn()) {
            $this->template->assign('isLoggedIn', true);
            $this->template->assign('username', $this->auth->getUsername());
            $this->template->assign('userRoles', $this->auth->getUserRoles());
        } else {
            $this->template->assign('isLoggedIn', false);
        }

        // Header und Template ausgeben
        $this->template->header();
        echo $this->template->render('home.tpl');
        $this->template->footer();
    }
}

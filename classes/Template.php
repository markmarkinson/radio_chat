<?php
class Template {
    private array $vars = [];
    private bool $headerSent = false;
    private bool $footerSent = false;

    /**
     * Variable an Template zuweisen
     */
    public function assign(string $name, $value): void {
        $this->vars[$name] = $value;
    }

    /**
     * Template rendern
     */
    public function render(string $templateFile): string {
        $templatePath = TEMPLATE_PATH . $templateFile;
        
        if (!file_exists($templatePath)) {
            error_log("Template nicht gefunden: " . $templatePath);
            return "<p>Template '{$templateFile}' nicht gefunden.</p>";
        }

        // Template-Variablen extrahieren
        extract($this->vars);
        
        // Output buffering starten
        ob_start();
        include $templatePath;
        return ob_get_clean();
    }

    /**
     * Seiten-Header ausgeben
     */
    public function header(): void {
        if ($this->headerSent) return;
        
        $headerTemplate = TEMPLATE_PATH . 'components/header.tpl';
        if (file_exists($headerTemplate)) {
            extract($this->vars);
            include $headerTemplate;
        } else {
            // Fallback-Header
            echo '<!DOCTYPE html><html><head><title>' . ($this->vars['pageTitle'] ?? 'Webradio Verwaltung') . '</title>';
            echo '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
            echo '<link rel="stylesheet" href="css/styles.css"></head><body>';
        }
        
        $this->headerSent = true;
    }

    /**
     * Seiten-Footer ausgeben
     */
    public function footer(): void {
        if ($this->footerSent) return;
        
        $footerTemplate = TEMPLATE_PATH . 'components/footer.tpl';
        if (file_exists($footerTemplate)) {
            extract($this->vars);
            include $footerTemplate;
        } else {
            // Fallback-Footer
            echo '</body></html>';
        }
        
        $this->footerSent = true;
    }

    /**
     * Fehlerseite anzeigen (wie im Original-System)
     */
    public function error(string $title = "Fehler", string $message = "", string $redirectUrl = "", int $delay = 3): void {
        if (!$this->headerSent) {
            $this->assign('pageTitle', $title);
            $this->header();
        }

        echo '<div class="error-container">';
        echo '<h1>' . htmlspecialchars($title) . '</h1>';
        
        if (!empty($message)) {
            echo '<div class="error-message">' . $message . '</div>';
        }
        
        if (!empty($redirectUrl)) {
            echo '<div class="redirect-info">Sie werden in ' . $delay . ' Sekunden weitergeleitet...</div>';
            echo '<script>setTimeout(() => window.location.href = "' . $redirectUrl . '", ' . ($delay * 1000) . ');</script>';
        }
        
        echo '</div>';
        
        if (!$this->footerSent) {
            $this->footer();
        }
        exit;
    }
}?>
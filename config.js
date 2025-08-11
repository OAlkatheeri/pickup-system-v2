// Configuration for the pickup system
window.APP_CONFIG = {
  SUPABASE_URL: "https://ikmahnxtovwhjppuzdpx.supabase.co",
  SUPABASE_ANON_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlrbWFobnh0b3Z3aGpwcHV6ZHB4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQ4NDk4MTAsImV4cCI6MjA3MDQyNTgxMH0.cLkpXqI-bVwGKknERc3vgqF-uXRh_hjIKArLTiK8y5w",
  SMS: {
    provider: "textbelt",
    endpoint: "https://textbelt.com/text",
    key: "textbelt"
  }
};

// Dynamically load dependencies
// Supabase client
// Axios for HTTP requests
// Leaflet for maps

document.write('<script src="https://unpkg.com/@supabase/supabase-js@2"></script>');
document.write('<script src="https://unpkg.com/axios/dist/axios.min.js"></script>');
document.write('<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />');
document.write('<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>');

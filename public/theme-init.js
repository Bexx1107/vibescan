(function() {
  try {
    localStorage.setItem('vibescan.theme_v2', 'dark');
    document.documentElement.setAttribute('data-theme', 'dark');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();

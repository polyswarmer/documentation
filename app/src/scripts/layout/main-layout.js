import MainMenu from './main-menu';
import SidebarNav from './sidebar-nav';

export default class MainLayout {
  constructor() {
    this.mainMenu = new MainMenu();
    this.sidebarNav = new SidebarNav();
  }

  init() {
    this.mainMenu.init();
    this.sidebarNav.init();
  }
}

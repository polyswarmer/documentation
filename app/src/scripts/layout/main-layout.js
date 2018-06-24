import MainMenu from './main-menu';
import ScrollSpy from './scroll-spy';

export default class MainLayout {
  constructor() {
    this.mainMenu = new MainMenu();
    this.scrollSpy = new ScrollSpy();
  }

  init() {
    this.mainMenu.init();
    this.scrollSpy.init();
  }
}

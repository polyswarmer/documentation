import MainMenu from './main-menu';

export default class MainLayout {
  constructor() {
    this.mainMenu = new MainMenu();
  }

  init() {
    this.mainMenu.init();
  }
}

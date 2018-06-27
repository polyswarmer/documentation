import MainLayout from '../layout/main-layout';
import Dropdown from '../components/dropdown';

export default class MainController {
  constructor() {
    this.mainLayout = new MainLayout();
    this.dropdown = new Dropdown();
  }

  init() {
    this.mainLayout.init();
    this.dropdown.init();
  }
}

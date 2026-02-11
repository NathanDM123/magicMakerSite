// Def d'une classe Diaporama
class Diaporama {
    constructor(classeCSS) {
        this.images = document.querySelectorAll(`.${classeCSS} img`); // selection de tt les img
        this.indexActuel = 0;
        this.demarrer();
    }

    changerImage() {
        if (this.images.length === 0) return;
        this.images[this.indexActuel].classList.remove('active');
        this.indexActuel = (this.indexActuel + 1) % this.images.length;
        this.images[this.indexActuel].classList.add('active');
    }

    demarrer() {
        setInterval(() => this.changerImage(), 3000);
    }
}

const monDiapo = new Diaporama("diaporama");
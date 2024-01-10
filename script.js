const puzzleContainer = document.getElementById('puzzleContainer');
const startButton = document.getElementById('startButton');
const timerDisplay = document.getElementById('timerDisplay');
const scoreDisplay = document.getElementById('scoreDisplay');
const gameContainer = document.getElementById('game-container');
const messageContainer = document.getElementById('message-container');
const messageText = document.getElementById('message-text');
const optionsContainer = document.getElementById('options-container');
const playAgainButton = document.getElementById('playAgainButton');
const quitButton = document.getElementById('quitButton');

const pieces = 20; // Number of puzzle pieces
let timer = 30;
let score = 0;
let interval;

// Shuffle array function
function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

// Function to start game
function startGame() {
  clearInterval(interval);
  timer = 30;
  score = 0;
  scoreDisplay.textContent = score;
  timerDisplay.textContent = timer;
  clearInterval(interval);
  interval = setInterval(() => {
    timer--;
    timerDisplay.textContent = timer;
    if (timer === 0) {
      endGame();
    }
  }, 1000);

  // Clear message and options containers
  messageContainer.style.display = 'none';
  optionsContainer.style.display = 'none';

  // Clear puzzle container
  puzzleContainer.innerHTML = '';

  const puzzlePieces = [];
  for (let i = 1; i <= pieces; i++) {
    puzzlePieces.push(i);
  }
  shuffleArray(puzzlePieces);

  puzzlePieces.forEach((num) => {
    const piece = document.createElement('div');
    piece.classList.add('puzzle-piece');
    piece.textContent = num;
    piece.setAttribute('draggable', true);
    piece.setAttribute('id', 'piece' + num); // Set unique IDs for pieces

    piece.addEventListener('dragstart', dragStart);
    piece.addEventListener('dragover', dragOver);
    piece.addEventListener('drop', dragDrop);

    puzzleContainer.appendChild(piece);
  });
}

startButton.addEventListener('click', startGame);

function dragStart(event) {
  event.dataTransfer.setData('text', event.target.id);
}

function dragOver(event) {
  event.preventDefault();
}

function dragDrop(event) {
  event.preventDefault();
  const data = event.dataTransfer.getData('text');
  const draggedElement = document.getElementById(data);
  const droppedElement = event.target;

  if (droppedElement.classList.contains('puzzle-piece')) {
    const temp = draggedElement.textContent;
    draggedElement.textContent = droppedElement.textContent;
    droppedElement.textContent = temp;

    // Check if puzzle is solved
    if (isPuzzleSolved()) {
      endGame();
    }

    // Update score
    score++;
    scoreDisplay.textContent = score;
  }
}

function isPuzzleSolved() {
  const puzzlePieces = puzzleContainer.querySelectorAll('.puzzle-piece');
  let isSolved = true;

  puzzlePieces.forEach((piece, index) => {
    if (parseInt(piece.textContent) !== index + 1) {
      isSolved = false;
    }
  });

  return isSolved;
}

function endGame() {
  clearInterval(interval);

  if (timer === 0) {
    messageText.textContent = `Game Over! Your score is ${calculateScore()}%`;
  } else {
    messageText.textContent = `Good Job! Your score is ${calculateScore()}%`;
  }

  messageContainer.style.display = 'block';
  optionsContainer.style.display = 'flex';
}

function calculateScore() {
  const maxScore = pieces * 2; // Maximum score for perfect arrangement
  const percentage = (score / maxScore) * 100;
  return Math.round(percentage);
}

playAgainButton.addEventListener('click', () => {
  gameContainer.style.display = 'block';
  messageContainer.style.display = 'none';
  optionsContainer.style.display = 'none';
  startGame();
});

quitButton.addEventListener('click', () => {
    window.location.href = 'worksheet.html'
  gameContainer.style.display = 'none';
  messageContainer.style.display = 'none';
  optionsContainer.style.display = 'none';
});

startGame(); // Start the game initially



function search(category) {
  const searchTerm = document.getElementById('searchInput').value;
  const url = `https://en.wikipedia.org/w/api.php?action=query&format=json&list=search&srsearch=${searchTerm}&origin=*`;

  fetch(url)
    .then(response => response.json())
    .then(data => {
      displayResults(data.query.search, category);
    })
    .catch(error => console.error('Error:', error));
}

function displayResults(results, category) {
  const searchResultsDiv = document.getElementById('searchResults');
  searchResultsDiv.innerHTML = '';

  results.forEach(result => {
    const title = result.title;
    const snippet = result.snippet;
    
    const resultDiv = document.createElement('div');
    resultDiv.innerHTML = `<h3>${title}</h3><p>${snippet}</p>`;
    
    searchResultsDiv.appendChild(resultDiv);
  });

  // Update the header with the selected category
  document.getElementById('searchResults').classList = 'results';
  document.getElementById('searchResults').classList.add(category);
}


/* Mental Game Script*/
const colors = ['#FF6633', '#FFB399', '#FF33FF', '#FFFF99', '#00B3E6', '#E6B333', '#3366E6', '#999966'];

const grid = document.getElementById('grid');
let firstColor = null;
let secondColor = null;
let attempts = 0;

function createGrid() {
  for (let i = 0; i < colors.length * 2; i++) {
    const gridItem = document.createElement('div');
    gridItem.classList.add('grid-item');
    gridItem.addEventListener('click', handleGridItemClick);
    grid.appendChild(gridItem);
  }
  assignColors();
}

function assignColors() {
  const gridItems = document.querySelectorAll('.grid-item');
  const randomColors = colors.concat(colors).sort(() => 0.5 - Math.random());

  gridItems.forEach((item, index) => {
    item.dataset.color = randomColors[index];
  });
}

function handleGridItemClick(event) {
  const clickedItem = event.target;

  if (clickedItem === firstColor || clickedItem === secondColor) {
    return;
  }

  clickedItem.style.backgroundColor = clickedItem.dataset.color;

  if (!firstColor) {
    firstColor = clickedItem;
  } else if (!secondColor) {
    secondColor = clickedItem;
    attempts++;
    checkMatch();
  }
}

function checkMatch() {
  if (firstColor.dataset.color === secondColor.dataset.color) {
    firstColor.removeEventListener('click', handleGridItemClick);
    secondColor.removeEventListener('click', handleGridItemClick);
    resetSelection();
    checkWin();
  } else {
    setTimeout(resetColors, 1000);
  }
}

function resetColors() {
  firstColor.style.backgroundColor = '#ccc';
  secondColor.style.backgroundColor = '#ccc';
  resetSelection();
}

function resetSelection() {
  firstColor = null;
  secondColor = null;
}

function checkWin() {
  const allItems = document.querySelectorAll('.grid-item');
  const matchedItems = document.querySelectorAll('.grid-item[style*="background-color"]');
  
  if (allItems.length === matchedItems.length) {
    alert(`Congratulations! You've completed the game in ${attempts} attempts.`);
  }
}

createGrid();

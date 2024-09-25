import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
// Getting the root element from the DOM where our React app will be mounted
const root = ReactDOM.createRoot(document.getElementById('root'));
// Rendering the App component inside the root DOM element
root.render(
    <React.StrictMode>
        <App/>
    </React.StrictMode>
);

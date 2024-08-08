from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import pickle
import logging
import os
from datetime import timedelta
from blockchain import Blockchain, vote
from utils.cleanup import clear_garbage
from utils.mining import mineblocktimer

import hashlib
import pickle

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Global variables
voterlist = []
voterkeys = {}
users = {
    "admin": {"password": "adminpass", "role": "admin"},
    "voter": {"password": "voterpass", "role": "voter"}
}
candidates = ["Candidate 1", "Candidate 2", "Candidate 3"]
voting_open = True  # Variable to control if voting is open

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not voting_open and request.form['username'] != 'admin':
            return 'Voting is closed'
        
        username = request.form['username']
        password = request.form['password']
        pin = request.form.get('pin', None)  # Get the pin if provided
        if username in users and users[username]['password'] == password:
            session['username'] = username
            session['role'] = users[username]['role']
            if users[username]['role'] == 'admin':
                return redirect(url_for('admin'))
            else:
                voterid = username
                if pin:
                    private_key, public_key = Blockchain.rsakeys()  # Generate keys
                    session['private_key'] = private_key
                    session['public_key'] = public_key
                    voterkeys[voterid] = {'pin': pin, 'public_key': public_key, 'private_key': private_key}

                    hidden_voter_id = hashlib.sha256((voterid + pin).encode('utf-8')).hexdigest()

                    if voterid not in voterlist:
                        voterlist.append(voterid)
                        with open('temp/VoterID_Database.txt', 'a') as f:
                            f.write(hidden_voter_id + '\n')
                        session['password'] = pin
                return redirect(url_for('voter'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if 'username' in session and session['role'] == 'admin':
        return render_template('admin.html')
    return redirect(url_for('index'))

@app.route('/voter')
def voter():
    if 'username' in session and session['role'] == 'voter':
        voterid = session['username']
        hidden_voter_id = hashlib.sha256((voterid + session['password']).encode('utf-8')).hexdigest()
        return render_template('vote.html', candidates=candidates, voterid=voterid, hidden_voter_id=hidden_voter_id)
    return redirect(url_for('index'))

@app.route('/vote', methods=['POST'])
def cast_vote():
    if not voting_open:
        return 'Voting is closed'
    
    candidate_id = request.form['candidate']
    voterid = request.form['voterid']
    hidden_voter_id = request.form['hidden_voter_id']
    if voterid in voterkeys:
        voter_public_key = voterkeys[voterid].get('public_key')
        new_vote = vote(hidden_voter_id, candidate_id, voter_public_key)
        if new_vote.verify():
            new_vote.save_vote()
            return redirect(url_for('thanks'))
        else:
            return redirect(url_for('oops'))
    return redirect(url_for('oops'))

@app.route('/thanks')
def thanks():
    return render_template('thanks.html')

@app.route('/role_selection')
def role_selection():
    return render_template('role_selection.html')

@app.route('/start_voting', methods=['POST'])
def start_voting():
    global voting_open
    voting_open = True
    return jsonify({"message": "Voting has been started by admin."})

@app.route('/stop_voting', methods=['POST'])
def stop_voting():
    global voting_open
    voting_open = False
    return jsonify({"message": "Voting has been stopped by admin."})

@app.route('/oops')
def oops():
    return render_template('oops.html')

@app.route('/display', methods=['GET'])
def display():
    blockchain = []
    try:
        with open('temp/blockchain.dat', 'rb') as blockfile:
            while True:
                try:
                    data = pickle.load(blockfile)
                    block = {
                        "Block Height": data.height,
                        "Data in block": data.data,
                        "Number of votes": data.number_of_votes,
                        "Merkle root": data.merkle,
                        "Difficulty": data.DIFFICULTY,
                        "Time stamp": data.timeStamp,
                        "Previous hash": data.prevHash,
                        "Block Hash": data.hash,
                        "Nonce": data.nonce
                    }
                    blockchain.append(block)
                except EOFError:
                    break
    except FileNotFoundError:
        return jsonify({"error": "Blockchain file not found!"})

    return jsonify(blockchain)

if __name__ == '__main__':
    # Ensure directories and files are set up
    if not os.path.exists('temp'):
        os.makedirs('temp')
    
    # Clear old files if needed (optional)
    clear_garbage()
    
    # Initialize blockchain
    blockchain = Blockchain()
    
    # Start block mining timer (if applicable)
    mineblocktimer()
    
    # Run Flask app
    app.run(debug=True)
import numpy as np
import random
from tqdm import tqdm

class GridWorld:
    def __init__(self, size=5):
        self.size = size
        self.state = (0, 0)
        self.goal = (size-1, size-1)
        self.done = False

    def reset(self):
        self.state = (0, 0)
        self.done = False
        return self.state

    def step(self, action):
        x, y = self.state
        if action == 0:  # up
            x = max(0, x - 1)
        elif action == 1:  # down
            x = min(self.size - 1, x + 1)
        elif action == 2:  # left
            y = max(0, y - 1)
        elif action == 3:  # right
            y = min(self.size - 1, y + 1)
        
        self.state = (x, y)
        
        if self.state == self.goal:
            reward = 1
            self.done = True
        else:
            reward = -0.1
        
        return self.state, reward, self.done

def train_q_learning(env, episodes=1000, alpha=0.1, gamma=0.99, epsilon=0.1):
    q_table = np.zeros((env.size, env.size, 4))
    
    for _ in tqdm(range(episodes), desc="Training"):
        state = env.reset()
        done = False
        
        while not done:
            if random.uniform(0, 1) < epsilon:
                action = random.choice(range(4))
            else:
                action = np.argmax(q_table[state])
            
            next_state, reward, done = env.step(action)
            
            old_q = q_table[state + (action,)]
            next_max = np.max(q_table[next_state])
            
            new_q = old_q + alpha * (reward + gamma * next_max - old_q)
            q_table[state + (action,)] = new_q
            
            state = next_state
    
    return q_table

def test_accuracy(env, q_table, episodes=100):
    success_count = 0
    total_rewards = 0
    
    for _ in range(episodes):
        state = env.reset()
        done = False
        episode_reward = 0
        
        while not done:
            action = np.argmax(q_table[state])
            state, reward, done = env.step(action)
            episode_reward += reward
        
        if state == env.goal:
            success_count += 1
        total_rewards += episode_reward
    
    accuracy = success_count / episodes
    average_reward = total_rewards / episodes
    
    return accuracy, average_reward

# Train the model
env = GridWorld(size=5)
q_table = train_q_learning(env, episodes=10000)

# Test the model
accuracy, avg_reward = test_accuracy(env, q_table, episodes=1000)

print(f"Model Accuracy: {accuracy:.2f}")
print(f"Average Reward: {avg_reward:.2f}")

# Optional: Visualize a single episode
def visualize_episode(env, q_table):
    state = env.reset()
    done = False
    path = [state]
    
    while not done:
        action = np.argmax(q_table[state])
        state, _, done = env.step(action)
        path.append(state)
    
    grid = np.full((env.size, env.size), '.')
    for i, (x, y) in enumerate(path):
        if i == 0:
            grid[x, y] = 'S'
        elif i == len(path) - 1:
            grid[x, y] = 'G'
        else:
            grid[x, y] = str(i)
    
    print("\nOptimal Path:")
    print(grid)

visualize_episode(env, q_table)
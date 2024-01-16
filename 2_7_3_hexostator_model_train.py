import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms
import numpy as np

# Define a custom dataset class
class CustomDataset(Dataset):
    def __init__(self, data, labels, transform=None):
        self.data = data
        self.labels = labels
        self.transform = transform

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        image = self.data[idx]
        label = self.labels[idx]

        if self.transform:
            image = self.transform(image)

        return image, label

class SimpleNN(nn.Module):
    def __init__(self):
        super(SimpleNN, self).__init__()
        self.fc1 = nn.Linear(16 * 16, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, 26)

    def forward(self, x):
        x = x.view(-1, 16 * 16)
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x

def main():
    # Hyperparameters
    learning_rate = 0.001
    batch_size = 64
    epochs = 10
    
    custom_labels = np.loadtxt("label_data.txt", dtype=np.int64)
    custom_data = np.loadtxt("image_data.txt", dtype=np.float32)
    custom_data = np.reshape(custom_data, (len(custom_labels), 16, 16))
    
    TRAIN_RATIO = 0.8
    
    train_cnt = round(len(custom_labels)*TRAIN_RATIO)
    
    # Create a custom dataset and DataLoader
    transform = transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.5,), (0.5,))])
    train_dataset = CustomDataset(data=custom_data[:train_cnt], labels=custom_labels[:train_cnt], transform=transform)
    train_loader = DataLoader(dataset=train_dataset, batch_size=batch_size, shuffle=True)
    
    model = SimpleNN()
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    
    # Training loop
    for epoch in range(epochs):
        for images, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
    
        print(f'Epoch [{epoch+1}/{epochs}], Loss: {loss.item():.4f}')
    
    test_dataset = CustomDataset(data=custom_data[train_cnt:], labels=custom_labels[train_cnt:], transform=transform)
    test_loader = DataLoader(dataset=test_dataset, batch_size=batch_size, shuffle=False)
    
    model.eval()
    correct = 0
    total = 0
    
    with torch.no_grad():
        for images, labels in test_loader:
            outputs = model(images)
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    
    accuracy = correct / total
    print(f'Test Accuracy: {accuracy * 100:.2f}%')
    
    torch.save(model.state_dict(), 'model_weights.pth')

if __name__ == "__main__":
    main()

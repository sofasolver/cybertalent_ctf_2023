import torch
import numpy as np
from model import SimpleNN


def relu(x):
    return np.maximum(0, x)

def main():
    model = SimpleNN()
    model.load_state_dict(torch.load("model_weights.pth"))

    lays = []
    for name, param in model.named_parameters():
        print(f"Parameter name: {name}, Size: {param.size()}")
        if param.requires_grad:
            lays.append(np.array(param.data))

    all_imgs = np.loadtxt("image_data.txt")
    all_labels = np.loadtxt("label_data.txt", dtype=np.int64)
    all_imgs = np.reshape(all_imgs, (len(all_labels), 256))

    for row in lays[0]:
        for x in row:
            print(f"{x:.5f},", end="")
        print()

    print()

    for x in lays[1]:
        print(f"{x:.5f},", end="")

    print()
    print()

    for row in lays[2]:
        for x in row:
            print(f"{x:.5f},", end="")
        print()

    for x in lays[3]:
        print(f"{x:.5f},", end="")

    print()
    print()
    correct = 0
    #for IDX in range(len(all_labels)):

    IDX = 0
    img = all_imgs[IDX]
    r1 = np.matmul(lays[0], img) # first weights
    print(r1[0])
    r2 = r1 + lays[1] # bias
    r3 = relu(r2) 
    r4 = np.matmul(lays[2], r3)  # second weights
    res = r4 + lays[3] # bias

    if np.argmax(res) == all_labels[IDX]:
        correct += 1

        #print(f"Predict: {chr(np.argmax(res)+ord('A'))}")
        #print(f"Correct: {chr(all_labels[IDX]+ord('A'))}")

    print(f"{100*correct/len(all_labels):.2f} %")



if __name__ == "__main__":
    main()

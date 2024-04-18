const brain = require('brain.js');
const fs = require('fs');

  const trainingData = JSON.parse(fs.readFileSync('services/data/brain/brain_sentiment_data.json', 'utf-8'));

  const modelPath = 'services/data/brain/brain_sentiment_model_001.json';
  const modelFile = fs.readFileSync(modelPath, 'utf-8');
  let net;

  if (fs.existsSync(modelPath) && modelFile) {
    net = new brain.recurrent.LSTM();
    net.fromJSON(JSON.parse(modelFile));
  } else {
    net = new brain.recurrent.LSTM({
      hiddenLayers: [32, 16], // Daha büyük ve daha derin bir model için gizli katmanları ve düğüm sayılarını artırabilirsiniz
      activation: 'leaky-relu',
      learningRate: 0.1, // Öğrenme hızını artırabilirsiniz
    });

    net.train(trainingData, {
      iterations: 5000, // Daha uzun süre eğitim için iterasyon sayısını artırabilirsiniz
      log: true,
      errorThresh: 0.005,
      momentum: 0.1,
      logPeriod: 10, // Her iterasyonda bir log mesajı almak için kullanabilirsiniz
    });

    const modelData = net.toJSON();
    fs.writeFileSync(modelPath, JSON.stringify(modelData), 'utf-8');
    console.log('model saved');
  }

function predictSentiment(text) {
  if (!text) {
    return 'write a message';
  } else if(text.length > 200) {
    return 'write a message in the appropriate range 0-200';
  } else {
    const output = net.run(text);
    return output;
  }
}

module.exports = { predictSentiment };

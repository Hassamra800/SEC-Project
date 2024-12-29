// Fetch sentiment trends
fetch('/api/sentiment_trends')
    .then(response => response.json())
    .then(data => {
        const ctx = document.getElementById('sentiment-trends-chart').getContext('2d');
        const labels = data.map(trend => trend.category);
        const scores = data.map(trend => trend.avg_score);

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Average Sentiment Score',
                    data: scores,
                    backgroundColor: ['rgba(75, 192, 192, 0.2)'],
                    borderColor: ['rgba(75, 192, 192, 1)'],
                    borderWidth: 1
                }]
            }
        });
    });

// Fetch heatmap data
fetch('/api/heatmap_data')
    .then(response => response.json())
    .then(data => {
        const ctx = document.getElementById('sentiment-heatmap-chart').getContext('2d');
        const labels = data.map(item => item.topic);
        const positive = data.map(item => item.positive);
        const neutral = data.map(item => item.neutral);
        const negative = data.map(item => item.negative);

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    { label: 'Positive', data: positive, backgroundColor: 'rgba(54, 162, 235, 0.2)' },
                    { label: 'Neutral', data: neutral, backgroundColor: 'rgba(255, 206, 86, 0.2)' },
                    { label: 'Negative', data: negative, backgroundColor: 'rgba(255, 99, 132, 0.2)' }
                ]
            }
        });
    });

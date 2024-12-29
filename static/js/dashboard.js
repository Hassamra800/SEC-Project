// Populate Dashboard with Dynamic Data
document.addEventListener("DOMContentLoaded", () => {
    fetch("/api/dashboard")
        .then((response) => response.json())
        .then((data) => {
            // Populate News Feed
            const feedList = document.getElementById("feed");
            data.personalized_feed.forEach((article) => {
                const li = document.createElement("li");
                li.textContent = `${article.title} (${article.sentiment})`;
                feedList.appendChild(li);
            });

            // Populate Topic Popularity
            const topicPopularity = document.getElementById("topic-popularity");
            for (const [topic, percentage] of Object.entries(data.topic_popularity)) {
                const li = document.createElement("li");
                li.textContent = `${topic}: ${percentage}%`;
                topicPopularity.appendChild(li);
            }

            // Populate Most Read Articles
            const mostRead = document.getElementById("most-read");
            data.most_read_articles.forEach((article) => {
                const li = document.createElement("li");
                li.textContent = `${article.title} - ${article.read_count} reads`;
                mostRead.appendChild(li);
            });

            // Populate User Stats
            document.getElementById("articles-read").textContent = data.user_stats.articles_read;
            document.getElementById("preferred-topics").textContent = data.user_stats.preferred_topics.join(", ");

            // Populate Trending Topics
            const trendingTopics = document.getElementById("trending-topics");
            data.trending_topics.forEach((topic) => {
                const li = document.createElement("li");
                li.textContent = topic;
                trendingTopics.appendChild(li);
            });
        })
        .catch((error) => console.error("Error loading dashboard data:", error));
});
